// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Hypervisor;
using Xunit;

namespace AgentGovernance.Tests;

public class SagaOrchestratorTests
{
    [Fact]
    public async Task Execute_AllStepsSucceed_Committed()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        var log = new List<string>();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => { log.Add("exec-1"); return "result-1"; },
            Compensate = async ct => { log.Add("undo-1"); }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-2",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => { log.Add("exec-2"); return "result-2"; },
            Compensate = async ct => { log.Add("undo-2"); }
        });

        var result = await orchestrator.ExecuteAsync(saga);

        Assert.True(result);
        Assert.Equal(SagaState.Committed, saga.State);
        Assert.Equal(new[] { "exec-1", "exec-2" }, log);
        Assert.Equal("result-1", saga.Steps[0].Result);
    }

    [Fact]
    public async Task Execute_StepFails_CompensatesInReverseOrder()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        var log = new List<string>();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => { log.Add("exec-1"); return null; },
            Compensate = async ct => { log.Add("undo-1"); }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-2",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => { log.Add("exec-2"); return null; },
            Compensate = async ct => { log.Add("undo-2"); }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-3",
            AgentDid = "did:agentmesh:a",
            Execute = ct => throw new InvalidOperationException("boom"),
            Compensate = async ct => { log.Add("undo-3"); }
        });

        var result = await orchestrator.ExecuteAsync(saga);

        Assert.False(result);
        Assert.Equal(SagaState.Aborted, saga.State);
        // Step 3 failed, so only steps 1 and 2 should be compensated, in reverse.
        Assert.Equal(new[] { "exec-1", "exec-2", "undo-2", "undo-1" }, log);
    }

    [Fact]
    public async Task Execute_CompensationFails_Escalated()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => null,
            Compensate = ct => throw new Exception("undo failed")
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-2",
            AgentDid = "did:agentmesh:a",
            Execute = ct => throw new Exception("fail")
        });

        var result = await orchestrator.ExecuteAsync(saga);

        Assert.False(result);
        Assert.Equal(SagaState.Escalated, saga.State);
        Assert.Contains("step-1", saga.FailedCompensations);
    }

    [Fact]
    public async Task Execute_StepTimeout_TriggersCompensation()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "slow-step",
            AgentDid = "did:agentmesh:a",
            Timeout = TimeSpan.FromMilliseconds(50),
            Execute = async ct => { await Task.Delay(5000, ct); return null; }
        });

        var result = await orchestrator.ExecuteAsync(saga);

        Assert.False(result);
        Assert.Equal(StepState.Failed, saga.Steps[0].State);
        Assert.Contains("timed out", saga.Steps[0].Error!);
    }

    [Fact]
    public async Task AddStep_ToExecutedSaga_Throws()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:agentmesh:a",
            Execute = async ct => null
        });

        // Start execution (will complete instantly).
        await orchestrator.ExecuteAsync(saga);

        Assert.Throws<InvalidOperationException>(() =>
            orchestrator.AddStep(saga, new SagaStep
            {
                ActionId = "late",
                AgentDid = "did:agentmesh:a",
                Execute = async ct => null
            }));
    }

    [Fact]
    public void GetSaga_ReturnsCreatedSaga()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        Assert.NotNull(orchestrator.GetSaga(saga.Id));
    }

    [Fact]
    public void GetSaga_UnknownId_ReturnsNull()
    {
        var orchestrator = new SagaOrchestrator();
        Assert.Null(orchestrator.GetSaga("nope"));
    }
}
