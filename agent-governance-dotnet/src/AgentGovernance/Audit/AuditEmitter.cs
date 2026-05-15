// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

namespace AgentGovernance.Audit;

/// <summary>
/// Thread-safe pub-sub audit event system for the governance engine.
/// Consumers subscribe to specific <see cref="GovernanceEventType"/> values
/// and receive callbacks when matching events are emitted.
/// </summary>
/// <remarks>
/// Handlers are invoked in subscription order: a handler registered earlier
/// fires before one registered later. Audit consumers (e.g. security correlation
/// or sequential log writers) can rely on this ordering.
///
/// Subscriptions can be removed with <see cref="Off"/> / <see cref="OffAll"/>;
/// callers must hold a reference to the exact delegate instance they passed
/// to <see cref="On"/> / <see cref="OnAll"/> in order to unsubscribe.
/// </remarks>
public sealed class AuditEmitter
{
    /// <summary>
    /// Handlers registered per event type. Mutations and snapshot reads are
    /// serialized through <see cref="_handlersLock"/>.
    /// </summary>
    private readonly Dictionary<GovernanceEventType, List<Action<GovernanceEvent>>> _handlers = new();

    /// <summary>
    /// Wildcard handlers that receive all events regardless of type. Guarded by <see cref="_handlersLock"/>.
    /// </summary>
    private readonly List<Action<GovernanceEvent>> _wildcardHandlers = new();

    private readonly object _handlersLock = new();

    /// <summary>
    /// Optional callback invoked when a handler throws an exception.
    /// Allows callers to log or monitor handler failures without disrupting other subscribers.
    /// </summary>
    public Action<Exception, GovernanceEvent>? HandlerError { get; init; }

    /// <summary>
    /// Subscribes a handler to a specific governance event type.
    /// Handlers fire in subscription order during <see cref="Emit(GovernanceEvent)"/>.
    /// </summary>
    /// <param name="type">The event type to listen for.</param>
    /// <param name="handler">The callback to invoke when a matching event is emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public void On(GovernanceEventType type, Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        lock (_handlersLock)
        {
            if (!_handlers.TryGetValue(type, out var list))
            {
                list = new List<Action<GovernanceEvent>>();
                _handlers[type] = list;
            }
            list.Add(handler);
        }
    }

    /// <summary>
    /// Subscribes a handler that receives all governance events (wildcard subscription).
    /// Wildcard handlers fire after the type-specific handlers, in subscription order.
    /// </summary>
    /// <param name="handler">The callback to invoke for every emitted event.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public void OnAll(Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_handlersLock)
        {
            _wildcardHandlers.Add(handler);
        }
    }

    /// <summary>
    /// Removes a previously registered type-specific handler. Removal is by delegate
    /// reference equality, so the caller must pass the same <see cref="Action{T}"/>
    /// instance that was originally subscribed via <see cref="On"/>.
    /// </summary>
    /// <param name="type">The event type the handler was subscribed to.</param>
    /// <param name="handler">The handler instance to remove.</param>
    /// <returns><c>true</c> if a matching handler was removed; <c>false</c> otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public bool Off(GovernanceEventType type, Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_handlersLock)
        {
            return _handlers.TryGetValue(type, out var list) && list.Remove(handler);
        }
    }

    /// <summary>
    /// Removes a previously registered wildcard handler. Removal is by delegate
    /// reference equality, so the caller must pass the same <see cref="Action{T}"/>
    /// instance that was originally subscribed via <see cref="OnAll"/>.
    /// </summary>
    /// <param name="handler">The handler instance to remove.</param>
    /// <returns><c>true</c> if a matching handler was removed; <c>false</c> otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public bool OffAll(Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_handlersLock)
        {
            return _wildcardHandlers.Remove(handler);
        }
    }

    /// <summary>
    /// Emits a pre-constructed <see cref="GovernanceEvent"/> to all matching subscribers.
    /// </summary>
    /// <param name="governanceEvent">The event to emit.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="governanceEvent"/> is <c>null</c>.</exception>
    public void Emit(GovernanceEvent governanceEvent)
    {
        ArgumentNullException.ThrowIfNull(governanceEvent);

        // Snapshot the handler arrays under the lock so user-supplied handlers
        // run without holding the lock (avoids deadlocks when a handler itself
        // calls back into the emitter to subscribe/unsubscribe).
        Action<GovernanceEvent>[] typed;
        Action<GovernanceEvent>[] wildcard;
        lock (_handlersLock)
        {
            typed = _handlers.TryGetValue(governanceEvent.Type, out var typedList) && typedList.Count > 0
                ? typedList.ToArray()
                : Array.Empty<Action<GovernanceEvent>>();
            wildcard = _wildcardHandlers.Count > 0
                ? _wildcardHandlers.ToArray()
                : Array.Empty<Action<GovernanceEvent>>();
        }

        foreach (var handler in typed)
        {
            InvokeSafe(handler, governanceEvent);
        }
        foreach (var handler in wildcard)
        {
            InvokeSafe(handler, governanceEvent);
        }
    }

    /// <summary>
    /// Constructs and emits a <see cref="GovernanceEvent"/> from individual parameters.
    /// This is a convenience overload for callers that don't need to pre-build the event.
    /// </summary>
    /// <param name="type">The event type.</param>
    /// <param name="agentId">The agent's DID.</param>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="data">Optional data dictionary to attach to the event.</param>
    /// <param name="policyName">Optional name of the policy that triggered this event.</param>
    public void Emit(
        GovernanceEventType type,
        string agentId,
        string sessionId,
        Dictionary<string, object>? data = null,
        string? policyName = null)
    {
        var governanceEvent = new GovernanceEvent
        {
            Type = type,
            AgentId = agentId,
            SessionId = sessionId,
            Data = data ?? new Dictionary<string, object>(),
            PolicyName = policyName
        };

        Emit(governanceEvent);
    }

    /// <summary>
    /// Returns the number of handlers registered for a specific event type.
    /// Useful for diagnostics and testing.
    /// </summary>
    /// <param name="type">The event type to query.</param>
    /// <returns>The number of registered handlers (excludes wildcard handlers).</returns>
    public int HandlerCount(GovernanceEventType type)
    {
        lock (_handlersLock)
        {
            return _handlers.TryGetValue(type, out var list) ? list.Count : 0;
        }
    }

    /// <summary>
    /// Returns the total number of wildcard handlers registered.
    /// </summary>
    public int WildcardHandlerCount
    {
        get
        {
            lock (_handlersLock)
            {
                return _wildcardHandlers.Count;
            }
        }
    }

    /// <summary>
    /// Safely invokes a handler, catching exceptions to prevent one faulty
    /// handler from disrupting other subscribers. Exceptions are surfaced
    /// through the <see cref="HandlerError"/> callback when configured.
    /// </summary>
    private void InvokeSafe(Action<GovernanceEvent> handler, GovernanceEvent governanceEvent)
    {
        try
        {
            handler(governanceEvent);
        }
        catch (Exception ex)
        {
            HandlerError?.Invoke(ex, governanceEvent);
        }
    }
}
