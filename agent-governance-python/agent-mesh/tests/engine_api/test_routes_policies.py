# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/policies and /policies/{id} (contract sections 7.2, 7.3).

These cover the counts-only gap fix: ``GET /api/v1/policies`` returns a paginated array of
``PolicySummary`` objects rather than a totals dict.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestListPolicies:
    def test_returns_paginated_summaries_not_counts(self, client):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        body = resp.json()
        # The gap fix: a top-level items array, not a {"total": N, ...} counts dict.
        assert isinstance(body["items"], list)
        assert "pagination" in body
        ids = [item["id"] for item in body["items"]]
        assert ids == ["alpha", "beta"]  # sorted by id

    def test_summary_fields_yaml(self, client):
        body = client.get("/api/v1/policies").json()
        alpha = next(i for i in body["items"] if i["id"] == "alpha")
        assert alpha["name"] == "Alpha Policy"
        assert alpha["description"] == "First sample policy"
        assert alpha["format"] == "yaml"
        assert alpha["source"] == "alpha.yaml"

    def test_summary_fields_json_without_description(self, client):
        body = client.get("/api/v1/policies").json()
        beta = next(i for i in body["items"] if i["id"] == "beta")
        assert beta["name"] == "Beta Policy"
        assert beta["description"] is None
        assert beta["format"] == "json"

    def test_pagination_metadata(self, client):
        body = client.get("/api/v1/policies").json()
        page = body["pagination"]
        assert page == {"page": 1, "limit": 20, "total": 2, "has_next": False}

    def test_pagination_slices(self, client):
        body = client.get("/api/v1/policies", params={"page": 2, "limit": 1}).json()
        assert [i["id"] for i in body["items"]] == ["beta"]
        assert body["pagination"]["has_next"] is False
        assert body["pagination"]["total"] == 2

    def test_empty_registry_returns_empty_items(self, empty_client):
        body = empty_client.get("/api/v1/policies").json()
        assert body["items"] == []
        assert body["pagination"]["total"] == 0

    @pytest.mark.parametrize(
        "params",
        [{"page": 0}, {"limit": 0}, {"limit": 101}, {"page": -1}],
    )
    def test_out_of_range_pagination_is_validation_error(self, client, params):
        resp = client.get("/api/v1/policies", params=params)
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"


class TestGetPolicy:
    def test_returns_full_detail(self, client):
        resp = client.get("/api/v1/policies/beta")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == "beta"
        assert body["rules_count"] == 2
        assert "Beta Policy" in body["content"]
        assert body["last_modified"]

    def test_yaml_detail_rules_count(self, client):
        body = client.get("/api/v1/policies/alpha").json()
        assert body["rules_count"] == 1
        assert body["format"] == "yaml"

    def test_unknown_id_is_not_found_envelope(self, client):
        resp = client.get("/api/v1/policies/does-not-exist")
        assert resp.status_code == 404
        body = resp.json()
        assert body["code"] == "POLICY_NOT_FOUND"
        assert body["status"] == 404
        assert body["details"]["id"] == "does-not-exist"
