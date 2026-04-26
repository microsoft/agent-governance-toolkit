# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP Kernel Server resources."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_kernel_server.resources import VFSResource, VFSResourceTemplate, ResourceContent


class TestResourceContent:
    def test_creation(self):
        rc = ResourceContent(uri="vfs://a/b", mime_type="application/json", content={"k": "v"})
        assert rc.uri == "vfs://a/b"
        assert rc.mime_type == "application/json"
        assert rc.content == {"k": "v"}
        assert rc.metadata == {}

    def test_with_metadata(self):
        rc = ResourceContent(
            uri="vfs://a/b", mime_type="text/plain", content="hello",
            metadata={"agent_id": "a"},
        )
        assert rc.metadata["agent_id"] == "a"


class TestVFSResource:
    def setup_method(self):
        self.vfs = VFSResource({"backend": "memory"})
        # Clear shared storage between tests
        VFSResource._storage.clear()

    @pytest.mark.asyncio
    async def test_write_and_read(self):
        await self.vfs.write("vfs://agent-1/mem/working/key", "value")
        result = await self.vfs.read("vfs://agent-1/mem/working/key")
        assert isinstance(result, ResourceContent)
        assert result.content == "value"

    @pytest.mark.asyncio
    async def test_read_nonexistent_returns_none(self):
        result = await self.vfs.read("vfs://agent-1/mem/working/nonexistent")
        assert result.content is None

    @pytest.mark.asyncio
    async def test_write_returns_resource_content(self):
        result = await self.vfs.write("vfs://agent-1/mem/working/key", {"data": 1})
        assert isinstance(result, ResourceContent)
        assert result.content["status"] == "written"

    @pytest.mark.asyncio
    async def test_write_to_policy_path_raises(self):
        with pytest.raises(PermissionError):
            await self.vfs.write("vfs://agent-1/policy/default", {"rules": []})

    @pytest.mark.asyncio
    async def test_read_metadata(self):
        await self.vfs.write("vfs://agent-1/mem/working/key", "val")
        result = await self.vfs.read("vfs://agent-1/mem/working/key")
        assert result.metadata["agent_id"] == "agent-1"
        assert "timestamp" in result.metadata

    def test_list_resources(self):
        resources = self.vfs.list_resources("agent-1")
        assert len(resources) == 3
        uris = {r["uri"] for r in resources}
        assert f"vfs://agent-1/mem/working" in uris
        assert f"vfs://agent-1/mem/episodic" in uris
        assert f"vfs://agent-1/policy" in uris

    def test_parse_uri_full(self):
        agent_id, path = self.vfs._parse_uri("vfs://agent-1/mem/working/key")
        assert agent_id == "agent-1"
        assert path == "mem/working/key"

    def test_parse_uri_no_path(self):
        agent_id, path = self.vfs._parse_uri("vfs://agent-1")
        assert agent_id == "agent-1"
        assert path == ""

    @pytest.mark.asyncio
    async def test_read_initial_storage_structure(self):
        result = await self.vfs.read("vfs://agent-1/mem")
        assert "working" in result.content
        assert "episodic" in result.content

    @pytest.mark.asyncio
    async def test_read_policy_default(self):
        result = await self.vfs.read("vfs://agent-1/policy/default")
        assert result.content["name"] == "default"
        assert "rules" in result.content

    @pytest.mark.asyncio
    async def test_write_multiple_keys(self):
        await self.vfs.write("vfs://agent-1/mem/working/k1", "v1")
        await self.vfs.write("vfs://agent-1/mem/working/k2", "v2")
        r1 = await self.vfs.read("vfs://agent-1/mem/working/k1")
        r2 = await self.vfs.read("vfs://agent-1/mem/working/k2")
        assert r1.content == "v1"
        assert r2.content == "v2"


class TestVFSResourceTemplate:
    def test_get_templates_returns_3(self):
        templates = VFSResourceTemplate.get_templates()
        assert len(templates) == 3

    def test_template_uris(self):
        templates = VFSResourceTemplate.get_templates()
        uris = [t["uriTemplate"] for t in templates]
        assert "vfs://{agent_id}/mem/working/{key}" in uris
        assert "vfs://{agent_id}/mem/episodic/{session_id}" in uris
        assert "vfs://{agent_id}/policy/{policy_name}" in uris

    def test_template_fields(self):
        templates = VFSResourceTemplate.get_templates()
        for t in templates:
            assert "name" in t
            assert "description" in t
            assert "mimeType" in t
