"""Tests for scanner base classes and registry."""


from agent_discovery.models import ScanResult
from agent_discovery.scanners.base import BaseScanner, ScannerRegistry
from agent_discovery.scanners.config import ConfigScanner


class MockScanner(BaseScanner):
    @property
    def name(self):
        return "mock"

    @property
    def description(self):
        return "A mock scanner for testing"

    async def scan(self, **kwargs):
        return ScanResult(scanner_name=self.name)


class TestScannerRegistry:
    def test_register_and_get(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        scanner = reg.get("mock")
        assert scanner is not None
        assert scanner.name == "mock"

    def test_get_nonexistent(self):
        reg = ScannerRegistry()
        assert reg.get("nonexistent") is None

    def test_list_scanners(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        assert "mock" in reg.list_scanners()

    def test_get_all(self):
        reg = ScannerRegistry()
        reg.register(MockScanner)
        scanners = reg.get_all()
        assert len(scanners) >= 1
        assert any(s.name == "mock" for s in scanners)


class TestGlobalRegistry:
    def test_builtin_scanners_registered(self):
        from agent_discovery.scanners.base import registry

        names = registry.list_scanners()
        assert "process" in names
        assert "config" in names
        assert "github" in names


class TestConfigScanner:
    async def test_finds_config_files_in_subdirectories(self, tmp_path):
        (tmp_path / ".agentmesh").mkdir()
        (tmp_path / ".agentmesh" / "config.yaml").write_text("", encoding="utf-8")
        (tmp_path / ".mcp").mkdir()
        (tmp_path / ".mcp" / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "crewai.yaml").write_text("", encoding="utf-8")

        result = await ConfigScanner().scan(paths=[str(tmp_path)])

        found = sorted(agent.tags["config_file"] for agent in result.agents)
        assert found == [".agentmesh/config.yaml", ".mcp/config.json", "crewai.yaml"]

    async def test_docker_file_in_subdirectory_uses_forward_slashes(self, tmp_path):
        (tmp_path / "services" / "api").mkdir(parents=True)
        (tmp_path / "services" / "api" / "Dockerfile").write_text(
            "RUN pip install crewai\n", encoding="utf-8"
        )

        result = await ConfigScanner().scan(paths=[str(tmp_path)])

        docker_agents = [agent for agent in result.agents if "docker_file" in agent.tags]
        assert [agent.tags["docker_file"] for agent in docker_agents] == ["services/api/Dockerfile"]
        assert docker_agents[0].name == "Containerized agent at services/api/Dockerfile"
