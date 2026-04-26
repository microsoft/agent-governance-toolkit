# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the SLI collector framework."""



from agent_sre.slo.indicators import (
    SLI,
    CostPerTask,
    DelegationChainDepth,
    PolicyCompliance,
    ResponseLatency,
    SLIRegistry,
    SLIValue,
    TaskSuccessRate,
    TimeWindow,
    ToolCallAccuracy,
)


class TestTimeWindow:
    def test_seconds(self) -> None:
        assert TimeWindow.HOUR_1.seconds == 3600
        assert TimeWindow.DAY_7.seconds == 604800
        assert TimeWindow.DAY_30.seconds == 2592000

    def test_from_string(self) -> None:
        assert TimeWindow("1h") == TimeWindow.HOUR_1
        assert TimeWindow("30d") == TimeWindow.DAY_30


class TestSLIValue:
    def test_creation(self) -> None:
        val = SLIValue(name="test", value=0.99)
        assert val.name == "test"
        assert val.value == 0.99
        assert val.timestamp > 0

    def test_is_good_with_target(self) -> None:
        good = SLIValue(name="test", value=0.99, metadata={"target": 0.95})
        assert good.is_good is True

        bad = SLIValue(name="test", value=0.90, metadata={"target": 0.95})
        assert bad.is_good is False

    def test_is_good_without_target(self) -> None:
        val = SLIValue(name="test", value=0.5)
        assert val.is_good is True  # No target = always good


class TestTaskSuccessRate:
    def test_basic_recording(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        assert sli.name == "task_success_rate"

        sli.record_task(True)
        sli.record_task(True)
        sli.record_task(False)

        val = sli.current_value()
        assert val is not None
        # 3 recordings of the running rate: 1.0, 1.0, 0.667
        # Average ≈ 0.889
        assert 0.5 < val < 1.0

    def test_compliance(self) -> None:
        sli = TaskSuccessRate(target=0.99)
        # Record enough failures to make running rate dip below target
        for _ in range(5):
            sli.record_task(False)
        for _ in range(95):
            sli.record_task(True)

        compliance = sli.compliance()
        assert compliance is not None
        # Early measurements had low rates (below 0.99 target)
        assert compliance < 1.0

    def test_collect(self) -> None:
        sli = TaskSuccessRate()
        sli.record_task(True)
        val = sli.collect()
        assert isinstance(val, SLIValue)
        assert val.value == 1.0

    def test_to_dict(self) -> None:
        sli = TaskSuccessRate(target=0.995, window="7d")
        sli.record_task(True)
        d = sli.to_dict()
        assert d["name"] == "task_success_rate"
        assert d["target"] == 0.995
        assert d["window"] == "7d"
        assert d["measurement_count"] == 1


class TestToolCallAccuracy:
    def test_recording(self) -> None:
        sli = ToolCallAccuracy(target=0.999)
        sli.record_call(True)
        sli.record_call(True)
        sli.record_call(False)
        val = sli.current_value()
        assert val is not None
        assert val < 1.0


class TestResponseLatency:
    def test_percentile(self) -> None:
        sli = ResponseLatency(target_ms=5000, percentile=0.95)
        for ms in [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
                    1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 10000]:
            sli.record_latency(ms)

        p95 = sli.current_value()
        assert p95 is not None
        assert p95 >= 1900  # P95 should be high

    def test_name_includes_percentile(self) -> None:
        sli = ResponseLatency(percentile=0.99)
        assert sli.name == "response_latency_p99"


class TestCostPerTask:
    def test_average_cost(self) -> None:
        sli = CostPerTask(target_usd=0.50)
        sli.record_cost(0.30)
        sli.record_cost(0.40)
        sli.record_cost(0.50)

        # Current value is the average of recorded rates
        val = sli.current_value()
        assert val is not None

    def test_collect(self) -> None:
        sli = CostPerTask()
        sli.record_cost(1.0)
        val = sli.collect()
        assert val.value == 1.0


class TestPolicyCompliance:
    def test_perfect_compliance(self) -> None:
        sli = PolicyCompliance()
        for _ in range(10):
            sli.record_check(True)
        val = sli.collect()
        assert val.value == 1.0

    def test_violation(self) -> None:
        sli = PolicyCompliance()
        sli.record_check(True)
        sli.record_check(False)
        val = sli.collect()
        assert val.value == 0.5


class TestDelegationChainDepth:
    def test_compliance(self) -> None:
        sli = DelegationChainDepth(max_depth=3)
        sli.record_depth(1)
        sli.record_depth(2)
        sli.record_depth(3)
        sli.record_depth(5)  # Exceeds max

        compliance = sli.compliance()
        assert compliance is not None
        assert compliance == 0.75  # 3 out of 4 within limit


class TestSLIRegistry:
    def test_built_in_types(self) -> None:
        registry = SLIRegistry()
        types = registry.list_types()
        assert "TaskSuccessRate" in types
        assert "ToolCallAccuracy" in types
        assert "ResponseLatency" in types
        assert "CostPerTask" in types
        assert "PolicyCompliance" in types
        assert "DelegationChainDepth" in types

    def test_get_type(self) -> None:
        registry = SLIRegistry()
        cls = registry.get_type("TaskSuccessRate")
        assert cls is TaskSuccessRate

    def test_register_instance(self) -> None:
        registry = SLIRegistry()
        sli = TaskSuccessRate()
        registry.register_instance("agent-1", sli)
        instances = registry.get_instances("agent-1")
        assert len(instances) == 1
        assert instances[0] is sli

    def test_collect_all(self) -> None:
        registry = SLIRegistry()
        sli = TaskSuccessRate()
        sli.record_task(True)
        registry.register_instance("agent-1", sli)
        values = registry.collect_all("agent-1")
        assert len(values) == 1
        assert values[0].value == 1.0

    def test_custom_type(self) -> None:
        class CustomSLI(SLI):
            def collect(self) -> SLIValue:
                return self.record(1.0)

        registry = SLIRegistry()
        registry.register_type(CustomSLI)
        assert "CustomSLI" in registry.list_types()
