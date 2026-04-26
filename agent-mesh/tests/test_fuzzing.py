# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Fuzz tests for identity and delegation parsers.

Exercises AgentIdentity, AgentDID, ScopeChain, DelegationLink,
and JWK import with malformed inputs to ensure clean error handling.
No crashes, unhandled exceptions, or hangs.
"""

import pytest
from pydantic import ValidationError

from agentmesh.exceptions import AgentMeshError
from agentmesh.identity.agent_id import AgentDID, AgentIdentity
from agentmesh.identity.delegation import ScopeChain, DelegationLink, UserContext

# ---------------------------------------------------------------------------
# Acceptable exception types — parsers must raise one of these or succeed
# ---------------------------------------------------------------------------
CLEAN_EXCEPTIONS = (ValueError, TypeError, AgentMeshError, ValidationError, KeyError, AttributeError)

# ---------------------------------------------------------------------------
# Malformed scalar inputs
# ---------------------------------------------------------------------------
MALFORMED_STRINGS: list = [
    "",
    " ",
    "\x00",
    "\x00" * 50,
    "a" * 200,
    "\n\r\t",
    "\ud800",  # lone surrogate (may cause codec errors)
    "\u200b\u200c\u200d",  # zero-width chars
    "\u202e\u202d",  # RTL/LTR override marks
    "null",
    "undefined",
    "true",
    "false",
    "<script>alert(1)</script>",
    "did:mesh:",  # valid prefix, empty id
    "did:mesh:" + "x" * 200,
]

# Kept separate to avoid Windows env-var length limits in pytest IDs
LONG_STRINGS: list = [
    "a" * 100_000,
    "did:mesh:" + "x" * 100_000,
]

MALFORMED_BYTES: list = [
    b"",
    b"\x00",
    b"\xff" * 100,
    b"not json",
    b'{"partial": true',
    b"null",
    b"[]",
    b"\xc0\xc1\xfe\xff",  # invalid UTF-8
    b"\x80\x81\x82",
    b"{}" * 50_000,
]

MALFORMED_DICTS: list = [
    {},
    {"unexpected": "field"},
    {"name": None},
    {"name": 42},
    {"name": []},
    {"name": {"nested": "object"}},
    {"name": "x", "public_key": None},
    {"did": "not-a-did"},
    {i: i for i in range(100)},  # numeric keys
    {"name": "a" * 200, "public_key": "b" * 200},
]

WRONG_TYPES: list = [None, 42, 3.14, True, False, [], (), set(), object()]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _valid_identity_dict() -> dict:
    """Return a minimal valid AgentIdentity dict for mutation testing."""
    ident = AgentIdentity.create(name="fuzz-agent", sponsor="fuzz@test.dev", capabilities=["read"])
    return ident.model_dump()


def assert_clean(callable_fn, *args, **kwargs):
    """Assert callable either succeeds or raises an acceptable exception."""
    try:
        callable_fn(*args, **kwargs)
    except CLEAN_EXCEPTIONS:
        pass  # expected
    except Exception as exc:
        pytest.fail(f"Unhandled exception {type(exc).__name__}: {exc}")


# ===========================================================================
# AgentDID fuzzing
# ===========================================================================
class TestAgentDIDFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_STRINGS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_from_string_malformed(self, val):
        assert_clean(AgentDID.from_string, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_STRINGS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_generate_malformed_name(self, val):
        assert_clean(AgentDID.generate, val)

    @pytest.mark.fuzz
    def test_from_string_long_inputs(self):
        """Test from_string with 100KB+ strings without bloating test IDs."""
        for val in LONG_STRINGS:
            assert_clean(AgentDID.from_string, val)


# ===========================================================================
# AgentIdentity constructor fuzzing
# ===========================================================================
class TestAgentIdentityFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_DICTS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_model_validate_malformed(self, val):
        assert_clean(AgentIdentity.model_validate, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("name", ""),
            ("name", " "),
            ("name", None),
            ("name", 42),
            ("name", "\x00" * 10),
            ("public_key", ""),
            ("public_key", " "),
            ("public_key", None),
            ("public_key", "not-base64!!!"),
            ("sponsor_email", ""),
            ("sponsor_email", "no-at-sign"),
            ("sponsor_email", None),
            ("sponsor_email", "@"),
            ("parent_did", "invalid-did"),
            ("parent_did", "did:wrong:method"),
            ("parent_did", ""),
            ("status", "unknown"),
            ("status", ""),
            ("status", 42),
            ("delegation_depth", -1),
            ("delegation_depth", "not-int"),
            ("delegation_depth", 999_999_999),
            ("capabilities", "not-a-list"),
            ("capabilities", [None, 42, []]),
        ],
    )
    def test_mutated_valid_dict(self, field, bad_value):
        """Take a valid dict, mutate one field, and verify clean handling."""
        data = _valid_identity_dict()
        data[field] = bad_value
        assert_clean(AgentIdentity.model_validate, data)

    @pytest.mark.fuzz
    def test_missing_required_fields(self):
        """Remove each required field from a valid dict."""
        required = ["did", "name", "public_key", "verification_key_id", "sponsor_email"]
        for field in required:
            data = _valid_identity_dict()
            del data[field]
            assert_clean(AgentIdentity.model_validate, data)

    @pytest.mark.fuzz
    def test_extra_unexpected_fields(self):
        data = _valid_identity_dict()
        data["evil_field"] = "x" * 100_000
        data["__proto__"] = {"admin": True}
        data["constructor"] = None
        assert_clean(AgentIdentity.model_validate, data)

    @pytest.mark.fuzz
    def test_long_string_fields(self):
        """Test 100KB+ strings in various fields without bloating test IDs."""
        long_str = "a" * 100_000
        for field in ["name", "public_key", "sponsor_email"]:
            data = _valid_identity_dict()
            data[field] = long_str
            assert_clean(AgentIdentity.model_validate, data)
        # Also test sponsor_email with @ and long string
        data = _valid_identity_dict()
        data["sponsor_email"] = long_str + "@x.com"
        assert_clean(AgentIdentity.model_validate, data)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "name,sponsor",
        [
            ("", "a@b.com"),
            ("x", ""),
            ("", ""),
            (None, "a@b.com"),
            ("x", None),
            ("x", "no-at"),
            ("\x00", "a@b.com"),
        ],
    )
    def test_create_factory_malformed(self, name, sponsor):
        assert_clean(AgentIdentity.create, name=name, sponsor=sponsor)

    @pytest.mark.fuzz
    def test_create_factory_long_strings(self):
        """Test create() with 100KB+ strings without bloating test IDs."""
        long_str = "a" * 100_000
        assert_clean(AgentIdentity.create, name=long_str, sponsor="a@b.com")
        assert_clean(AgentIdentity.create, name="x", sponsor=long_str + "@b.com")


# ===========================================================================
# JWK import fuzzing
# ===========================================================================
class TestJWKFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", WRONG_TYPES + MALFORMED_DICTS, ids=lambda v: repr(v)[:60])
    def test_from_jwk_malformed(self, val):
        assert_clean(AgentIdentity.from_jwk, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "jwk",
        [
            {"kty": "OKP"},  # missing crv, x
            {"kty": "OKP", "crv": "Ed25519"},  # missing x
            {"kty": "RSA", "crv": "Ed25519", "x": "AAAA"},  # wrong kty
            {"kty": "OKP", "crv": "P-256", "x": "AAAA"},  # wrong curve
            {"kty": "OKP", "crv": "Ed25519", "x": "!!!invalid-b64!!!"},
            {"kty": "OKP", "crv": "Ed25519", "x": ""},
            {"kty": "OKP", "crv": "Ed25519", "x": "AAAA" * 100_000},  # huge key
            {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "d": "!!!"},
            {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "d": ""},
            {"kty": None, "crv": None, "x": None},
            {"kty": 42, "crv": 42, "x": 42},
        ],
        ids=lambda v: repr(v)[:80],
    )
    def test_from_jwk_edge_cases(self, jwk):
        assert_clean(AgentIdentity.from_jwk, jwk)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "jwks",
        [
            {},  # missing keys
            {"keys": []},  # empty keys
            {"keys": "not-a-list"},
            {"keys": [None]},
            {"keys": [42]},
            {"keys": [{}]},
            {"keys": [{"kty": "OKP"}]},
            None,
            42,
            [],
        ],
        ids=lambda v: repr(v)[:60],
    )
    def test_from_jwks_malformed(self, jwks):
        assert_clean(AgentIdentity.from_jwks, jwks)

    @pytest.mark.fuzz
    def test_from_jwks_with_bad_kid(self):
        ident = AgentIdentity.create(name="k", sponsor="k@k.dev")
        jwks = ident.to_jwks()
        assert_clean(AgentIdentity.from_jwks, jwks, kid="nonexistent-kid")


# ===========================================================================
# ScopeChain fuzzing
# ===========================================================================
class TestScopeChainFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_DICTS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_model_validate_malformed(self, val):
        assert_clean(ScopeChain.model_validate, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("chain_id", ""),
            ("chain_id", " "),
            ("chain_id", None),
            ("root_sponsor_email", ""),
            ("root_sponsor_email", "no-at"),
            ("root_sponsor_email", None),
            ("root_capabilities", []),
            ("root_capabilities", None),
            ("root_capabilities", "not-a-list"),
            ("leaf_did", ""),
            ("leaf_did", "invalid"),
            ("leaf_did", None),
            ("max_depth", -1),
            ("max_depth", 0),
            ("max_depth", "not-int"),
            ("links", "not-a-list"),
            ("links", [None]),
            ("links", [42]),
            ("links", [{}]),
        ],
    )
    def test_mutated_valid_chain(self, field, bad_value):
        """Create a valid chain dict, mutate one field, verify clean handling."""
        chain, _ = ScopeChain.create_root(
            sponsor_email="test@test.dev",
            root_agent_did="did:mesh:abc123",
            capabilities=["read"],
        )
        data = chain.model_dump()
        data[field] = bad_value
        assert_clean(ScopeChain.model_validate, data)

    @pytest.mark.fuzz
    def test_missing_required_fields(self):
        chain, _ = ScopeChain.create_root(
            sponsor_email="test@test.dev",
            root_agent_did="did:mesh:abc123",
            capabilities=["read"],
        )
        required = ["chain_id", "root_sponsor_email", "root_capabilities", "leaf_did"]
        for field in required:
            data = chain.model_dump()
            del data[field]
            assert_clean(ScopeChain.model_validate, data)

    @pytest.mark.fuzz
    def test_extra_unexpected_fields(self):
        chain, _ = ScopeChain.create_root(
            sponsor_email="test@test.dev",
            root_agent_did="did:mesh:abc123",
            capabilities=["read"],
        )
        data = chain.model_dump()
        data["evil"] = {"nested": {"deep": True}}
        data["__class__"] = "ScopeChain"
        assert_clean(ScopeChain.model_validate, data)


# ===========================================================================
# DelegationLink fuzzing
# ===========================================================================
class TestDelegationLinkFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_DICTS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_model_validate_malformed(self, val):
        assert_clean(DelegationLink.model_validate, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("link_id", ""),
            ("link_id", None),
            ("depth", -1),
            ("depth", "nan"),
            ("parent_did", None),
            ("child_did", None),
            ("parent_capabilities", None),
            ("parent_capabilities", "string-not-list"),
            ("delegated_capabilities", None),
            ("delegated_capabilities", [None, 42]),
            ("parent_signature", None),
            ("link_hash", None),
            ("previous_link_hash", {"nested": "object"}),
        ],
    )
    def test_mutated_valid_link(self, field, bad_value):
        _, link = ScopeChain.create_root(
            sponsor_email="test@test.dev",
            root_agent_did="did:mesh:abc123",
            capabilities=["read"],
        )
        data = link.model_dump()
        data[field] = bad_value
        assert_clean(DelegationLink.model_validate, data)


# ===========================================================================
# UserContext fuzzing
# ===========================================================================
class TestUserContextFuzzing:
    @pytest.mark.fuzz
    @pytest.mark.parametrize("val", MALFORMED_DICTS + WRONG_TYPES, ids=lambda v: repr(v)[:60])
    def test_model_validate_malformed(self, val):
        assert_clean(UserContext.model_validate, val)

    @pytest.mark.fuzz
    @pytest.mark.parametrize(
        "field,bad_value",
        [
            ("user_id", ""),
            ("user_id", None),
            ("user_id", 42),
            ("roles", "not-a-list"),
            ("permissions", None),
            ("metadata", "not-a-dict"),
            ("metadata", [1, 2, 3]),
        ],
    )
    def test_mutated_valid_context(self, field, bad_value):
        ctx = UserContext.create(user_id="u1", user_email="u@u.dev")
        data = ctx.model_dump()
        data[field] = bad_value
        assert_clean(UserContext.model_validate, data)


# ===========================================================================
# Programmatic fuzz: bulk random-ish inputs
# ===========================================================================
class TestBulkFuzzing:
    """Generate many malformed inputs programmatically."""

    BULK_INPUTS: list = [
        b"",
        b"\x00",
        b"\xff" * 100,
        b"not json",
        b'{"partial": true',
        b"null",
        b"[]",
        "a" * 200,
        None,
        42,
        [],
        {},
        b"\xc0\xc1\xfe\xff",
        "\x00" * 1000,
        "}" * 1000,
        '{"a":' * 100,  # deeply nested incomplete JSON
        "\ufeff" + "data",  # BOM prefix
        "a" * 100_000,  # extreme length
    ]

    @pytest.mark.fuzz
    def test_agent_did_bulk(self):
        for inp in self.BULK_INPUTS:
            assert_clean(AgentDID.from_string, inp)

    @pytest.mark.fuzz
    def test_agent_identity_bulk(self):
        for inp in self.BULK_INPUTS:
            assert_clean(AgentIdentity.model_validate, inp)

    @pytest.mark.fuzz
    def test_from_jwk_bulk(self):
        for inp in self.BULK_INPUTS:
            assert_clean(AgentIdentity.from_jwk, inp)

    @pytest.mark.fuzz
    def test_scope_chain_bulk(self):
        for inp in self.BULK_INPUTS:
            assert_clean(ScopeChain.model_validate, inp)

    @pytest.mark.fuzz
    def test_delegation_link_bulk(self):
        for inp in self.BULK_INPUTS:
            assert_clean(DelegationLink.model_validate, inp)
