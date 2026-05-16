// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Hypervisor;

/// <summary>
/// State of the saga transaction.
/// </summary>
public enum SagaState
{
    /// <summary>Saga is created but not yet started.</summary>
    Pending,

    /// <summary>Saga steps are executing.</summary>
    Executing,

    /// <summary>All steps completed successfully.</summary>
    Committed,

    /// <summary>A step failed; compensation is running.</summary>
    Compensating,

    /// <summary>Compensation completed; saga is rolled back.</summary>
    Aborted,

    /// <summary>Compensation itself failed; manual intervention needed.</summary>
    Escalated
}

/// <summary>
/// State of an individual saga step.
/// </summary>
public enum StepState
{
    /// <summary>Step has not started.</summary>
    Pending,
    /// <summary>Step is currently executing.</summary>
    Executing,
    /// <summary>Step completed successfully.</summary>
    Committed,
    /// <summary>Step execution failed.</summary>
    Failed,
    /// <summary>Step was rolled back by its compensating action.</summary>
    Compensated,
    /// <summary>Compensation itself failed, requiring manual intervention.</summary>
    CompensationFailed
}

/// <summary>
/// A single step in a saga with forward execution and compensating (undo) action.
/// </summary>
public sealed class SagaStep
{
    private int _maxAttempts = 3;

    /// <summary>Unique identifier for this saga step action.</summary>
    public required string ActionId { get; init; }
    /// <summary>DID of the agent executing this step.</summary>
    public required string AgentDid { get; init; }
    /// <summary>Current execution state of this step.</summary>
    public StepState State { get; internal set; } = StepState.Pending;
    /// <summary>Error message if the step failed or compensation failed.</summary>
    public string? Error { get; internal set; }

    /// <summary>
    /// Maximum number of execution attempts (including the initial attempt).
    /// For example, <c>MaxAttempts = 3</c> means 1 initial try + up to 2 retries.
    /// Default is 3.
    /// </summary>
    public int MaxAttempts { get => _maxAttempts; init => _maxAttempts = value; }

    /// <summary>
    /// Obsolete: use <see cref="MaxAttempts"/> instead. This property controlled total
    /// attempts (not retry count), which was confusing. It now maps to <see cref="MaxAttempts"/>.
    /// </summary>
    [Obsolete("Use MaxAttempts instead. MaxRetries controlled total attempts, not retry count.")]
    public int MaxRetries { get => _maxAttempts; init => _maxAttempts = value; }

    /// <summary>Timeout for executing this step before it is cancelled.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The forward execution function. Returns a result object on success.
    /// </summary>
    public required Func<CancellationToken, Task<object?>> Execute { get; init; }

    /// <summary>
    /// The compensating function to undo this step. Called during rollback.
    /// </summary>
    public Func<CancellationToken, Task>? Compensate { get; init; }

    /// <summary>The result returned by the Execute function.</summary>
    public object? Result { get; internal set; }
}

/// <summary>
/// Represents a saga transaction tracking all steps and their states.
/// </summary>
public sealed class Saga
{
    /// <summary>Unique identifier for this saga instance.</summary>
    public string Id { get; } = Guid.NewGuid().ToString("N")[..12];
    /// <summary>Current aggregate state of the saga transaction.</summary>
    public SagaState State { get; internal set; } = SagaState.Pending;
    /// <summary>Ordered list of steps in this saga.</summary>
    public List<SagaStep> Steps { get; } = new();
    /// <summary>Action IDs of steps whose compensation failed during rollback.</summary>
    public List<string> FailedCompensations { get; } = new();
    /// <summary>UTC timestamp when this saga was created.</summary>
    public DateTime CreatedUtc { get; } = DateTime.UtcNow;

    /// <summary>
    /// Per-saga lock for synchronizing state mutations during execution and compensation.
    /// </summary>
    internal object SyncRoot { get; } = new();
}

/// <summary>
/// Orchestrates multi-step agent transactions using the saga pattern.
/// Steps execute in sequence; on failure, committed steps are compensated
/// in reverse order to maintain consistency.
/// </summary>
public sealed class SagaOrchestrator
{
    private readonly Dictionary<string, Saga> _sagas = new();
    private readonly object _lock = new();

    /// <summary>
    /// Creates a new saga and returns it.
    /// </summary>
    public Saga CreateSaga()
    {
        var saga = new Saga();
        lock (_lock)
        {
            _sagas[saga.Id] = saga;
        }
        return saga;
    }

    /// <summary>
    /// Adds a step to an existing saga.
    /// </summary>
    public void AddStep(Saga saga, SagaStep step)
    {
        ArgumentNullException.ThrowIfNull(saga);
        ArgumentNullException.ThrowIfNull(step);
        if (saga.State != SagaState.Pending)
            throw new InvalidOperationException("Cannot add steps to a saga that is already executing.");
        saga.Steps.Add(step);
    }

    /// <summary>
    /// Executes all saga steps in sequence. On failure, compensates committed steps
    /// in reverse order.
    /// </summary>
    /// <param name="saga">The saga to execute.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>true</c> if all steps committed; <c>false</c> if the saga was aborted.</returns>
    public async Task<bool> ExecuteAsync(Saga saga, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(saga);
        lock (saga.SyncRoot) { saga.State = SagaState.Executing; }

        foreach (var step in saga.Steps)
        {
            var success = await ExecuteStepAsync(saga, step, cancellationToken).ConfigureAwait(false);
            if (!success)
            {
                await CompensateAsync(saga, cancellationToken).ConfigureAwait(false);
                return false;
            }
        }

        lock (saga.SyncRoot) { saga.State = SagaState.Committed; }
        return true;
    }

    /// <summary>
    /// Retrieves a saga by ID.
    /// </summary>
    public Saga? GetSaga(string sagaId)
    {
        lock (_lock)
        {
            return _sagas.GetValueOrDefault(sagaId);
        }
    }

    private async Task<bool> ExecuteStepAsync(Saga saga, SagaStep step, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < step.MaxAttempts; attempt++)
        {
            lock (saga.SyncRoot) { step.State = StepState.Executing; step.Error = null; }

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(step.Timeout);

                var result = await step.Execute(cts.Token).ConfigureAwait(false);
                lock (saga.SyncRoot) { step.Result = result; step.State = StepState.Committed; }
                return true;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lock (saga.SyncRoot) { step.Error = $"Step '{step.ActionId}' timed out after {step.Timeout.TotalSeconds}s."; }
            }
            catch (Exception)
            {
                lock (saga.SyncRoot) { step.Error = $"Step '{step.ActionId}' failed — see server logs"; }
            }

            // Stop retrying if the caller cancelled the operation
            if (cancellationToken.IsCancellationRequested)
                break;

            if (attempt + 1 < step.MaxAttempts)
            {
                var delay = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        lock (saga.SyncRoot) { step.State = StepState.Failed; }
        return false;
    }

    private async Task CompensateAsync(Saga saga, CancellationToken cancellationToken)
    {
        List<SagaStep> committedSteps;
        lock (saga.SyncRoot)
        {
            saga.State = SagaState.Compensating;
            committedSteps = saga.Steps
                .Where(s => s.State == StepState.Committed)
                .Reverse()
                .ToList();
        }

        foreach (var step in committedSteps)
        {
            if (step.Compensate is null)
            {
                lock (saga.SyncRoot) { step.State = StepState.Compensated; }
                continue;
            }

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(step.Timeout);

                await step.Compensate(cts.Token).ConfigureAwait(false);
                lock (saga.SyncRoot) { step.State = StepState.Compensated; }
            }
            catch (Exception)
            {
                lock (saga.SyncRoot)
                {
                    step.State = StepState.CompensationFailed;
                    step.Error = $"Compensation for '{step.ActionId}' failed — see server logs";
                    saga.FailedCompensations.Add(step.ActionId);
                }
            }
        }

        lock (saga.SyncRoot)
        {
            saga.State = saga.FailedCompensations.Count > 0
                ? SagaState.Escalated
                : SagaState.Aborted;
        }
    }
}
