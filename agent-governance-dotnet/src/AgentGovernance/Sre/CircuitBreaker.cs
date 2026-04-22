// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Sre;

/// <summary>
/// State of a circuit breaker.
/// </summary>
public enum CircuitState
{
    /// <summary>Normal operation — requests pass through.</summary>
    Closed,

    /// <summary>Failures exceeded threshold — requests are blocked.</summary>
    Open,

    /// <summary>Testing recovery — limited requests allowed through.</summary>
    HalfOpen
}

/// <summary>
/// Configuration for a <see cref="CircuitBreaker"/>.
/// </summary>
public sealed class CircuitBreakerConfig
{
    /// <summary>Number of consecutive failures before opening the circuit.</summary>
    public int FailureThreshold { get; init; } = 5;

    /// <summary>Time to wait in Open state before transitioning to HalfOpen.</summary>
    public TimeSpan ResetTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Number of probe calls allowed in HalfOpen state.</summary>
    public int HalfOpenMaxCalls { get; init; } = 1;
}

/// <summary>
/// Exception thrown when a circuit breaker is open and rejecting requests.
/// </summary>
public sealed class CircuitBreakerOpenException : Exception
{
    /// <summary>Estimated time until the circuit breaker transitions to HalfOpen.</summary>
    public TimeSpan RetryAfter { get; }

    /// <summary>
    /// Initializes a new instance with the estimated retry delay.
    /// </summary>
    /// <param name="retryAfter">Time until the circuit transitions to half-open.</param>
    public CircuitBreakerOpenException(TimeSpan retryAfter)
        : base($"Circuit breaker is open. Retry after {retryAfter.TotalSeconds:F0}s.")
    {
        RetryAfter = retryAfter;
    }
}

/// <summary>
/// Three-state circuit breaker for preventing cascading failures in agent chains.
/// <list type="bullet">
///   <item><b>Closed</b> — Normal operation. Failures are counted.</item>
///   <item><b>Open</b> — Failures exceeded threshold. All calls are rejected with <see cref="CircuitBreakerOpenException"/>.</item>
///   <item><b>HalfOpen</b> — Testing recovery. A limited number of probe calls are allowed through.</item>
/// </list>
/// </summary>
public sealed class CircuitBreaker
{
    private readonly CircuitBreakerConfig _config;
    private readonly object _lock = new();

    private CircuitState _state = CircuitState.Closed;
    private int _failureCount;
    private int _halfOpenCalls;
    private long _lastFailureTicks;
    private long _openedAtTicks;

    /// <summary>Current state of the circuit breaker.</summary>
    public CircuitState State
    {
        get
        {
            lock (_lock)
            {
                MaybeTransition();
                return _state;
            }
        }
    }

    /// <summary>Current consecutive failure count.</summary>
    public int FailureCount { get { lock (_lock) { return _failureCount; } } }

    /// <summary>
    /// Initializes a new <see cref="CircuitBreaker"/>.
    /// </summary>
    /// <param name="config">Optional configuration. Uses defaults if <c>null</c>.</param>
    public CircuitBreaker(CircuitBreakerConfig? config = null)
    {
        _config = config ?? new CircuitBreakerConfig();
    }

    /// <summary>
    /// Executes an action through the circuit breaker.
    /// </summary>
    /// <typeparam name="T">Return type of the action.</typeparam>
    /// <param name="action">The action to execute.</param>
    /// <returns>The result of the action.</returns>
    /// <exception cref="CircuitBreakerOpenException">Thrown when the circuit is open.</exception>
    public async Task<T> ExecuteAsync<T>(Func<Task<T>> action)
    {
        EnsureCallAllowed();

        try
        {
            var result = await action().ConfigureAwait(false);
            RecordSuccess();
            return result;
        }
        catch (Exception)
        {
            RecordFailure();
            throw;
        }
    }

    /// <summary>
    /// Executes a void action through the circuit breaker.
    /// </summary>
    public async Task ExecuteAsync(Func<Task> action)
    {
        EnsureCallAllowed();

        try
        {
            await action().ConfigureAwait(false);
            RecordSuccess();
        }
        catch (Exception)
        {
            RecordFailure();
            throw;
        }
    }

    /// <summary>
    /// Records a successful operation, transitioning from HalfOpen to Closed.
    /// </summary>
    public void RecordSuccess()
    {
        lock (_lock)
        {
            if (_state == CircuitState.HalfOpen)
            {
                _state = CircuitState.Closed;
                _failureCount = 0;
                _halfOpenCalls = 0;
            }
            else if (_state == CircuitState.Closed)
            {
                _failureCount = 0;
            }
        }
    }

    /// <summary>
    /// Records a failed operation. Opens the circuit if the failure threshold is reached.
    /// </summary>
    public void RecordFailure()
    {
        lock (_lock)
        {
            _failureCount++;
            _lastFailureTicks = Environment.TickCount64;

            if (_state == CircuitState.HalfOpen)
            {
                // Any failure in HalfOpen immediately reopens.
                TransitionToOpen();
            }
            else if (_state == CircuitState.Closed && _failureCount >= _config.FailureThreshold)
            {
                TransitionToOpen();
            }
        }
    }

    /// <summary>
    /// Manually resets the circuit breaker to Closed state.
    /// </summary>
    public void Reset()
    {
        lock (_lock)
        {
            _state = CircuitState.Closed;
            _failureCount = 0;
            _halfOpenCalls = 0;
        }
    }

    private void EnsureCallAllowed()
    {
        lock (_lock)
        {
            MaybeTransition();

            switch (_state)
            {
                case CircuitState.Open:
                    var elapsedMs = Math.Max(0, Environment.TickCount64 - _openedAtTicks);
                    var elapsed = TimeSpan.FromMilliseconds(elapsedMs);
                    var retryAfter = _config.ResetTimeout - elapsed;
                    if (retryAfter < TimeSpan.Zero) retryAfter = TimeSpan.Zero;
                    throw new CircuitBreakerOpenException(retryAfter);

                case CircuitState.HalfOpen:
                    if (_halfOpenCalls >= _config.HalfOpenMaxCalls)
                    {
                        throw new CircuitBreakerOpenException(_config.ResetTimeout);
                    }
                    _halfOpenCalls++;
                    break;

                case CircuitState.Closed:
                    break;
            }
        }
    }

    private void MaybeTransition()
    {
        if (_state == CircuitState.Open)
        {
            var elapsed = TimeSpan.FromMilliseconds(Environment.TickCount64 - _openedAtTicks);
            if (elapsed >= _config.ResetTimeout)
            {
                _state = CircuitState.HalfOpen;
                _halfOpenCalls = 0;
            }
        }
    }

    private void TransitionToOpen()
    {
        _state = CircuitState.Open;
        _openedAtTicks = Environment.TickCount64;
    }
}
