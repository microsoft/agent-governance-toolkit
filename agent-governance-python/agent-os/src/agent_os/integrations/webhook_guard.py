# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""SSRF guard for outbound webhook and classifier calls.

Every outbound HTTP call this package makes to an operator-configured URL
(approval webhooks, the HTTP advisory classifier) goes through a
:class:`WebhookEndpointGuard`. The guard mirrors the .NET
``WebhookApprover`` so the SDKs block the same destinations:

* **At construction** :meth:`WebhookEndpointGuard.validate_url` rejects
  non-http(s) schemes, blocked host names (``localhost`` and its
  subdomains, the cloud metadata names and their subdomains, with case and
  trailing-dot normalisation) and literal addresses inside a blocked range,
  including decimal, hex, octal and short IPv4 spellings and IPv4-mapped or
  IPv4-compatible IPv6 forms.
* **At connect time** the guard resolves the host itself, rejects the
  request when *any* resolved address is blocked, and opens the socket to
  the exact address it validated. The HTTP client never resolves the name
  again, so a DNS answer that changes between validation and connect
  (rebinding) cannot steer the request.
* The opener follows no redirects (a 3xx is an error, never fetched),
  ignores proxy environment variables, and speaks only http and https.

Blocked ranges: loopback, unspecified, link-local (``169.254.0.0/16``
including the metadata endpoint, ``fe80::/10``), private (RFC 1918,
``fc00::/7``), shared address space ``100.64.0.0/10``, multicast, the
documentation and benchmark ranges, and everything ``ipaddress`` marks as
reserved or non-global.

Operators who must deliver to an internal endpoint opt in explicitly::

    guard = WebhookEndpointGuard.allowing(["10.20.0.0/16", "hooks.corp.internal"])
    approver = VersionedWebhookApproval(url, endpoint_guard=guard)

The default guard allows nothing internal. Tests inject a ``resolver`` so
no network is needed.

This module is intentionally stdlib-only. It ships twice, as
``agentmesh/governance/webhook_guard.py`` and
``agent_os/integrations/webhook_guard.py``, because neither package can
import the other's development checkout. Keep both copies identical; a
test in each package checks that.
"""

from __future__ import annotations

import functools
import http.client
import ipaddress
import socket
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Union
from urllib.parse import urlparse

__all__ = [
    "AddressResolver",
    "DEFAULT_GUARD",
    "WebhookEndpointBlockedError",
    "WebhookEndpointGuard",
    "default_resolver",
]

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Maps a host name to the address strings it resolves to. Injected in tests.
AddressResolver = Callable[[str], Iterable[str]]


class WebhookEndpointBlockedError(ValueError):
    """The webhook endpoint names or resolves to a blocked address."""


# Names blocked outright together with every subdomain.
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google",
    "metadata.google.internal",
})

# Explicit ranges, matching the .NET IsBlockedAddress table. The
# ``ipaddress`` predicates below cover most of these already; the explicit
# list closes the gaps (100.64/10, 192.0.0/24, 192.88.99/24, multicast,
# site-local) and keeps the policy readable.
_BLOCKED_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
        "2001:db8::/32",
    )
)


def _normalize_hostname(host: str) -> str:
    """Lower-case, strip IPv6 brackets and trailing dots."""
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.rstrip(".")


def _is_blocked_hostname(host: str) -> bool:
    return any(
        host == blocked or host.endswith("." + blocked)
        for blocked in _BLOCKED_HOSTNAMES
    )


def _normalize_address(address: IPAddress) -> IPAddress:
    """Unwrap IPv4-mapped (``::ffff:a.b.c.d``) and IPv4-compatible
    (``::a.b.c.d``) IPv6 addresses so the IPv4 ranges apply to them."""
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
        value = int(address)
        if 1 < value < 2**32:
            return ipaddress.IPv4Address(value)
    return address


def _is_blocked_address(address: IPAddress) -> bool:
    address = _normalize_address(address)
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
        or not address.is_global
    ):
        return True
    return any(
        address.version == network.version and address in network
        for network in _BLOCKED_NETWORKS
    )


def _parse_literal(host: str) -> IPAddress | None:
    """Return the address a literal host spells, or None for a DNS name.

    ``ipaddress`` handles the canonical forms (and IPv6 zone ids);
    ``getaddrinfo`` with ``AI_NUMERICHOST`` never touches DNS but accepts the
    ``inet_aton`` spellings (``2130706433``, ``0x7f000001``, ``017700000001``,
    ``127.1``, ``0``) that a resolver would otherwise turn into loopback.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, flags=socket.AI_NUMERICHOST)
    except (OSError, UnicodeError, ValueError):
        return None
    for info in infos:
        try:
            return ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
    return None


def default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to every A and AAAA record via the system resolver."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


@dataclass(frozen=True)
class WebhookEndpointGuard:
    """Destination policy for outbound webhook calls. Denies internal
    destinations unless they appear in the allow list.

    Attributes:
        allowed_hosts: Host names (lower-case, no trailing dot) exempt from
            every check. Their resolved addresses are still pinned.
        allowed_networks: Networks whose addresses are accepted even when
            they fall inside a blocked range.
        resolver: Maps a host name to its address strings. Defaults to the
            system resolver; tests inject one.
    """

    allowed_hosts: frozenset[str] = frozenset()
    allowed_networks: tuple[IPNetwork, ...] = ()
    resolver: AddressResolver = default_resolver

    @classmethod
    def allowing(
        cls,
        entries: Iterable[str] | None = None,
        *,
        resolver: AddressResolver | None = None,
    ) -> WebhookEndpointGuard:
        """Build a guard that exempts ``entries``: host names, IP literals
        or CIDR networks. An empty list yields the default deny-all guard."""
        hosts: set[str] = set()
        networks: list[IPNetwork] = []
        for entry in entries or ():
            text = entry.strip()
            if not text:
                raise ValueError("allow-list entries must not be empty")
            try:
                networks.append(ipaddress.ip_network(_normalize_hostname(text), strict=False))
            except ValueError:
                hosts.add(_normalize_hostname(text))
        return cls(
            allowed_hosts=frozenset(hosts),
            allowed_networks=tuple(networks),
            resolver=resolver or default_resolver,
        )

    def with_resolver(self, resolver: AddressResolver) -> WebhookEndpointGuard:
        return WebhookEndpointGuard(self.allowed_hosts, self.allowed_networks, resolver)

    # -- policy -----------------------------------------------------------

    def _is_allowed_address(self, address: IPAddress) -> bool:
        normalized = _normalize_address(address)
        return any(
            candidate.version == network.version and candidate in network
            for network in self.allowed_networks
            for candidate in (address, normalized)
        )

    def is_blocked_address(self, address: IPAddress | str) -> bool:
        """True when ``address`` is inside a blocked range and not allow-listed."""
        if isinstance(address, str):
            address = ipaddress.ip_address(address)
        return _is_blocked_address(address) and not self._is_allowed_address(address)

    def validate_url(self, url: str) -> None:
        """Construction-time check: scheme, host name denylist and literal
        addresses. Raises :class:`ValueError` (or its subclass
        :class:`WebhookEndpointBlockedError`) on a rejected URL."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Unsupported URL scheme '{parsed.scheme}': only http and https are allowed"
            )
        try:
            raw_host = parsed.hostname
            parsed.port  # noqa: B018 - raises ValueError on a malformed port
        except ValueError as exc:
            raise ValueError(f"Malformed webhook URL authority: {exc}") from exc
        if not raw_host:
            raise ValueError("Webhook URL has no host")
        host = _normalize_hostname(raw_host)
        if host in self.allowed_hosts:
            return
        literal = _parse_literal(host)
        if literal is not None:
            if self.is_blocked_address(literal):
                raise WebhookEndpointBlockedError(
                    f"URL host '{host}' is blocked to prevent SSRF"
                )
        elif _is_blocked_hostname(host):
            raise WebhookEndpointBlockedError(
                f"URL host '{host}' is blocked to prevent SSRF"
            )

    def resolve_allowed_addresses(self, host: str) -> list[str]:
        """Connect-time check: resolve ``host`` and return its addresses, or
        raise :class:`WebhookEndpointBlockedError` when any of them is
        blocked. Resolution failures propagate as :class:`OSError`."""
        host = _normalize_hostname(host)
        if not host:
            raise WebhookEndpointBlockedError("Webhook URL has no host")
        exempt = host in self.allowed_hosts
        literal = _parse_literal(host)
        if literal is not None:
            raw_addresses = [str(literal)]
        else:
            if not exempt and _is_blocked_hostname(host):
                raise WebhookEndpointBlockedError(
                    f"URL host '{host}' is blocked to prevent SSRF"
                )
            raw_addresses = list(self.resolver(host))
        if not raw_addresses:
            raise OSError(f"webhook endpoint '{host}' did not resolve to any address")
        addresses: list[IPAddress] = []
        for raw in raw_addresses:
            try:
                addresses.append(ipaddress.ip_address(raw))
            except ValueError as exc:
                raise OSError(
                    f"webhook endpoint '{host}' resolved to an invalid address {raw!r}"
                ) from exc
        if not exempt:
            for address in addresses:
                if self.is_blocked_address(address):
                    raise WebhookEndpointBlockedError(
                        f"URL host '{host}' resolves to blocked address {address} "
                        "(SSRF guard)"
                    )
        return [str(address) for address in addresses]

    # -- transport --------------------------------------------------------

    def build_opener(self) -> urllib.request.OpenerDirector:
        """An opener that pins connections to validated addresses, follows no
        redirects, ignores proxy settings and handles only http(s)."""
        opener = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.UnknownHandler(),
            urllib.request.HTTPDefaultErrorHandler(),
            urllib.request.HTTPErrorProcessor(),
            _GuardedHTTPHandler(self),
            _GuardedHTTPSHandler(self),
        ):
            opener.add_handler(handler)
        return opener

    def open(
        self, request: urllib.request.Request, timeout: float | None = None
    ) -> http.client.HTTPResponse:
        """Send ``request`` through the guarded opener. Validates the URL
        again first, so a URL swapped after construction is still checked."""
        self.validate_url(request.full_url)
        return self.build_opener().open(request, timeout=timeout)


DEFAULT_GUARD = WebhookEndpointGuard()


def _connect_pinned(connection: http.client.HTTPConnection, guard: WebhookEndpointGuard) -> None:
    """Resolve through the guard and connect to the first reachable validated
    address. Mirrors ``HTTPConnection.connect`` minus the client-side DNS."""
    addresses = guard.resolve_allowed_addresses(connection.host)
    last_error: OSError | None = None
    for address in addresses:
        try:
            sock = socket.create_connection(
                (address, connection.port), connection.timeout, connection.source_address
            )
        except OSError as exc:
            last_error = exc
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        connection.sock = sock
        return
    if last_error is None:
        raise OSError(f"webhook endpoint '{connection.host}' has no address to connect to")
    raise last_error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, guard: WebhookEndpointGuard, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._guard = guard

    def connect(self) -> None:
        _connect_pinned(self, self._guard)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, guard: WebhookEndpointGuard, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._guard = guard

    def connect(self) -> None:
        _connect_pinned(self, self._guard)
        # TLS still verifies the certificate against the host name, not the
        # pinned address.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, guard: WebhookEndpointGuard) -> None:
        super().__init__()
        self._guard = guard

    def http_open(self, req):
        return self.do_open(functools.partial(_PinnedHTTPConnection, guard=self._guard), req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, guard: WebhookEndpointGuard) -> None:
        super().__init__()
        self._guard = guard

    def https_open(self, req):
        return self.do_open(
            functools.partial(_PinnedHTTPSConnection, guard=self._guard),
            req,
            context=self._context,
        )
