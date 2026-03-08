// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;

namespace AgentGovernance.Audit;

/// <summary>
/// Thread-safe pub-sub audit event system for the governance engine.
/// Consumers subscribe to specific <see cref="GovernanceEventType"/> values
/// and receive callbacks when matching events are emitted.
/// </summary>
public sealed class AuditEmitter
{
    /// <summary>
    /// Handlers registered per event type.
    /// </summary>
    private readonly ConcurrentDictionary<GovernanceEventType, ConcurrentBag<Action<GovernanceEvent>>> _handlers = new();

    /// <summary>
    /// Wildcard handlers that receive all events regardless of type.
    /// </summary>
    private readonly ConcurrentBag<Action<GovernanceEvent>> _wildcardHandlers = new();

    /// <summary>
    /// Subscribes a handler to a specific governance event type.
    /// </summary>
    /// <param name="type">The event type to listen for.</param>
    /// <param name="handler">The callback to invoke when a matching event is emitted.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public void On(GovernanceEventType type, Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        var bag = _handlers.GetOrAdd(type, _ => new ConcurrentBag<Action<GovernanceEvent>>());
        bag.Add(handler);
    }

    /// <summary>
    /// Subscribes a handler that receives all governance events (wildcard subscription).
    /// </summary>
    /// <param name="handler">The callback to invoke for every emitted event.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="handler"/> is <c>null</c>.</exception>
    public void OnAll(Action<GovernanceEvent> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _wildcardHandlers.Add(handler);
    }

    /// <summary>
    /// Emits a pre-constructed <see cref="GovernanceEvent"/> to all matching subscribers.
    /// </summary>
    /// <param name="governanceEvent">The event to emit.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="governanceEvent"/> is <c>null</c>.</exception>
    public void Emit(GovernanceEvent governanceEvent)
    {
        ArgumentNullException.ThrowIfNull(governanceEvent);

        // Notify type-specific handlers.
        if (_handlers.TryGetValue(governanceEvent.Type, out var handlers))
        {
            foreach (var handler in handlers)
            {
                InvokeSafe(handler, governanceEvent);
            }
        }

        // Notify wildcard handlers.
        foreach (var handler in _wildcardHandlers)
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
        return _handlers.TryGetValue(type, out var handlers) ? handlers.Count : 0;
    }

    /// <summary>
    /// Returns the total number of wildcard handlers registered.
    /// </summary>
    public int WildcardHandlerCount => _wildcardHandlers.Count;

    /// <summary>
    /// Safely invokes a handler, catching and swallowing any exceptions
    /// to prevent one faulty handler from disrupting other subscribers.
    /// </summary>
    private static void InvokeSafe(Action<GovernanceEvent> handler, GovernanceEvent governanceEvent)
    {
        try
        {
            handler(governanceEvent);
        }
        catch
        {
            // Swallow handler exceptions to maintain event bus stability.
            // In production, consider logging handler errors.
        }
    }
}
