# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""``agt cred`` — manage the credential vault for agent tool calls.

Subcommands:

    agt cred add NAME VALUE          Store or replace a credential.
    agt cred list                    List credential handle names.
    agt cred rotate NAME NEW_VALUE   Rotate a credential value in place.
    agt cred remove NAME             Delete a credential.
    agt cred genkey                  Generate a Fernet encryption key.

The CLI persists to ``$AGT_VAULT_PATH`` (default ``./.agt/vault.bin``)
encrypted with ``$AGT_VAULT_KEY`` (a Fernet key — generate with
``agt cred genkey``). The CLI never prints credential values.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click


_DEFAULT_VAULT_PATH = ".agt/vault.bin"


def _resolve_vault() -> "object":  # returns CredentialVault
    """Construct a vault from environment-configured key/path."""
    try:
        from agent_os.credential_vault import (
            CredentialVault,
            EncryptionUnavailable,
        )
    except ImportError as exc:
        raise click.ClickException(
            f"agent_os.credential_vault is unavailable: {exc}"
        ) from exc

    path = os.environ.get("AGT_VAULT_PATH", _DEFAULT_VAULT_PATH)
    key = os.environ.get("AGT_VAULT_KEY")
    if not key:
        raise click.ClickException(
            "AGT_VAULT_KEY is not set. Generate one with 'agt cred genkey' "
            "and export it before running other 'agt cred' commands."
        )
    Path(os.path.dirname(path) or ".").mkdir(parents=True, exist_ok=True)
    try:
        return CredentialVault(persist_path=path, encryption_key=key.encode("utf-8"))
    except EncryptionUnavailable as exc:
        raise click.ClickException(str(exc)) from exc


@click.group(name="cred")
def cred() -> None:
    """Manage the AGT credential vault."""


@cred.command(name="genkey")
def genkey() -> None:
    """Print a fresh Fernet encryption key suitable for AGT_VAULT_KEY."""
    from agent_os.credential_vault import CredentialVault

    click.echo(CredentialVault.generate_key().decode("ascii"))


@cred.command(name="add")
@click.argument("name")
@click.argument("value")
@click.option("--type", "cred_type", default="secret", show_default=True,
              help="Credential type label (e.g. bearer_token, basic_auth).")
def add(name: str, value: str, cred_type: str) -> None:
    """Store or replace a credential. Use '-' as VALUE to read from stdin."""
    vault = _resolve_vault()
    if value == "-":
        value = sys.stdin.read().rstrip("\n")
    handle = vault.put(name, value, cred_type=cred_type)  # type: ignore[attr-defined]
    click.echo(f"stored: {handle.name}")


@cred.command(name="list")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
def list_handles(as_json: bool) -> None:
    """List credential handle names (no values are printed)."""
    vault = _resolve_vault()
    names = vault.list_handles()  # type: ignore[attr-defined]
    if as_json:
        click.echo(json.dumps({"handles": names}))
        return
    if not names:
        click.echo("(no credentials)")
        return
    for n in names:
        meta = vault.get_metadata(n) or {}  # type: ignore[attr-defined]
        click.echo(f"{n}\t{meta.get('cred_type', '')}\tv{meta.get('version', 1)}")


@cred.command(name="rotate")
@click.argument("name")
@click.argument("new_value")
def rotate(name: str, new_value: str) -> None:
    """Rotate a credential's value while preserving its handle name."""
    vault = _resolve_vault()
    if new_value == "-":
        new_value = sys.stdin.read().rstrip("\n")
    try:
        handle = vault.rotate(name, new_value)  # type: ignore[attr-defined]
    except KeyError:
        raise click.ClickException(f"unknown credential: {name}")
    click.echo(f"rotated: {handle.name}")


@cred.command(name="remove")
@click.argument("name")
def remove(name: str) -> None:
    """Delete a credential by handle name."""
    vault = _resolve_vault()
    removed = vault.delete(name)  # type: ignore[attr-defined]
    if not removed:
        raise click.ClickException(f"unknown credential: {name}")
    click.echo(f"removed: {name}")
