"""Tests for langgraph_trust.edges — trust_edge and trust_router."""

from langgraph_trust.edges import trust_edge, trust_router


class TestTrustEdge:
    def test_pass_routes_correctly(self):
        route = trust_edge(pass_node="execute", fail_node="quarantine")
        result = route({"trust_result": {"verdict": "pass"}})
        assert result == "execute"

    def test_fail_routes_correctly(self):
        route = trust_edge(pass_node="execute", fail_node="quarantine")
        result = route({"trust_result": {"verdict": "fail"}})
        assert result == "quarantine"

    def test_review_routes_to_fail_by_default(self):
        route = trust_edge(pass_node="execute", fail_node="quarantine")
        result = route({"trust_result": {"verdict": "review"}})
        assert result == "quarantine"

    def test_review_routes_to_review_node(self):
        route = trust_edge(
            pass_node="execute",
            fail_node="quarantine",
            review_node="human_review",
        )
        result = route({"trust_result": {"verdict": "review"}})
        assert result == "human_review"

    def test_missing_trust_result_fails(self):
        route = trust_edge(pass_node="execute", fail_node="quarantine")
        result = route({})
        assert result == "quarantine"

    def test_unknown_verdict_fails(self):
        route = trust_edge(pass_node="execute", fail_node="quarantine")
        result = route({"trust_result": {"verdict": "unknown"}})
        assert result == "quarantine"


class TestTrustRouter:
    def test_basic_routing(self):
        route = trust_router({
            "pass": "execute",
            "fail": "quarantine",
            "review": "human_review",
        })
        assert route({"trust_result": {"verdict": "pass"}}) == "execute"
        assert route({"trust_result": {"verdict": "fail"}}) == "quarantine"
        assert route({"trust_result": {"verdict": "review"}}) == "human_review"

    def test_default_route(self):
        route = trust_router({"pass": "go"}, default="fallback")
        assert route({"trust_result": {"verdict": "fail"}}) == "fallback"

    def test_missing_state_uses_default(self):
        route = trust_router({"pass": "go"}, default="stop")
        assert route({}) == "stop"
