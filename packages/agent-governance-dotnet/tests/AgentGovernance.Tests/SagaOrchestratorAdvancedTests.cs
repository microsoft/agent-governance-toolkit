// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Hypervisor;
using Xunit;

namespace AgentGovernance.Tests;

public class SagaOrchestratorAdvancedTests
{
    [Fact]
    public async Task Execute_StepRetries_SucceedsOnRetry()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        int attempts = 0;

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "flaky",
            AgentDid = "did:mesh:a",
            MaxAttempts = 2,
            Execute = async ct =>
            {
                attempts++;
                if (attempts < 2) throw new InvalidOperationException("fail");
                return "ok";
            }
        });

        var result = await orchestrator.ExecuteAsync(saga);
        Assert.True(result);
        Assert.Equal(2, attempts);
    }

    [Fact]
    public async Task Execute_StepExhaustsRetries_Fails()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        int attempts = 0;

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "always-fails",
            AgentDid = "did:mesh:a",
            MaxAttempts = 2,
            Execute = ct => { attempts++; throw new Exception("fail"); }
        });

        var result = await orchestrator.ExecuteAsync(saga);
        Assert.False(result);
        Assert.Equal(2, attempts); // MaxAttempts=2 means 2 total attempts
    }

    [Fact]
    public async Task Execute_StepNoCompensator_SkipsCompensation()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        var log = new List<string>();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:mesh:a",
            Execute = async ct => { log.Add("exec-1"); return null; }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-2-fails",
            AgentDid = "did:mesh:a",
            Execute = ct => throw new Exception("boom")
        });

        await orchestrator.ExecuteAsync(saga);
        Assert.Equal(SagaState.Aborted, saga.State);
    }

    [Fact]
    public async Task Execute_CancellationToken_StopsExecution()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        var cts = new CancellationTokenSource();
        int executed = 0;

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-1",
            AgentDid = "did:mesh:a",
            Execute = async ct => { executed++; cts.Cancel(); return null; }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "step-2",
            AgentDid = "did:mesh:a",
            Timeout = TimeSpan.FromMilliseconds(100),
            Execute = async ct => { ct.ThrowIfCancellationRequested(); return null; }
        });

        var result = await orchestrator.ExecuteAsync(saga, cts.Token);
        Assert.False(result);
    }

    [Fact]
    public async Task Execute_ManySteps_AllSucceed()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        int completed = 0;

        for (int i = 0; i < 50; i++)
        {
            orchestrator.AddStep(saga, new SagaStep
            {
                ActionId = $"step-{i}",
                AgentDid = "did:mesh:a",
                Execute = async ct => { Interlocked.Increment(ref completed); return null; }
            });
        }

        Assert.True(await orchestrator.ExecuteAsync(saga));
        Assert.Equal(50, completed);
    }

    [Fact]
    public async Task Execute_LargeSaga_FailMiddle_CompensatesCorrectly()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        var compensated = new List<string>();

        for (int i = 0; i < 10; i++)
        {
            var idx = i;
            orchestrator.AddStep(saga, new SagaStep
            {
                ActionId = $"step-{idx}",
                AgentDid = "did:mesh:a",
                Execute = idx == 5
                    ? ct => throw new Exception("mid-fail")
                    : async ct => null,
                Compensate = async ct => { lock (compensated) compensated.Add($"step-{idx}"); }
            });
        }

        await orchestrator.ExecuteAsync(saga);
        Assert.Equal(SagaState.Aborted, saga.State);
        Assert.Equal(5, compensated.Count);
        // Verify reverse order.
        for (int i = 0; i < 5; i++)
            Assert.Equal($"step-{4 - i}", compensated[i]);
    }

    [Fact]
    public void CreateSaga_UniqueIds()
    {
        var orchestrator = new SagaOrchestrator();
        var ids = new HashSet<string>();
        for (int i = 0; i < 100; i++)
            Assert.True(ids.Add(orchestrator.CreateSaga().Id));
    }

    [Fact]
    public async Task Execute_StoresResult()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s1",
            AgentDid = "did:mesh:a",
            Execute = async ct => "the-result"
        });
        await orchestrator.ExecuteAsync(saga);
        Assert.Equal("the-result", saga.Steps[0].Result);
        Assert.Equal(StepState.Committed, saga.Steps[0].State);
    }

    [Fact]
    public async Task Execute_FailedStep_HasError()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "bad",
            AgentDid = "did:mesh:a",
            Execute = ct => throw new InvalidOperationException("Something went wrong")
        });
        await orchestrator.ExecuteAsync(saga);
        Assert.Equal(StepState.Failed, saga.Steps[0].State);
        Assert.Contains("Something went wrong", saga.Steps[0].Error!);
    }

    [Fact]
    public async Task Execute_EmptySaga_Commits()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        Assert.True(await orchestrator.ExecuteAsync(saga));
        Assert.Equal(SagaState.Committed, saga.State);
    }

    [Fact]
    public async Task Execute_MultipleCompensationFailures_Escalated()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s1",
            AgentDid = "did:mesh:a",
            Execute = async ct => null,
            Compensate = ct => throw new Exception("undo fail")
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s2",
            AgentDid = "did:mesh:a",
            Execute = async ct => null,
            Compensate = ct => throw new Exception("undo fail 2")
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s3-boom",
            AgentDid = "did:mesh:a",
            Execute = ct => throw new Exception("exec fail")
        });

        await orchestrator.ExecuteAsync(saga);
        Assert.Equal(SagaState.Escalated, saga.State);
        Assert.Contains("s1", saga.FailedCompensations);
        Assert.Contains("s2", saga.FailedCompensations);
    }

    [Fact]
    public async Task Execute_TimeoutOnSecondStep_FirstCompensated()
    {
        var orchestrator = new SagaOrchestrator();
        var saga = orchestrator.CreateSaga();
        bool compensated = false;

        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s1",
            AgentDid = "did:mesh:a",
            Execute = async ct => "ok",
            Compensate = async ct => { compensated = true; }
        });
        orchestrator.AddStep(saga, new SagaStep
        {
            ActionId = "s2-slow",
            AgentDid = "did:mesh:a",
            Timeout = TimeSpan.FromMilliseconds(50),
            Execute = async ct => { await Task.Delay(5000, ct); return null; }
        });

        await orchestrator.ExecuteAsync(saga);
        Assert.True(compensated);
        Assert.Contains("timed out", saga.Steps[1].Error!);
    }
}
