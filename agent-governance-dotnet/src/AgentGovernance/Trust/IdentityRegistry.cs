// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

namespace AgentGovernance.Trust;

/// <summary>
/// A thread-safe registry for managing <see cref="AgentIdentity"/> instances.
/// Supports registration, lookup, revocation, and querying of agent identities.
/// </summary>
public sealed class IdentityRegistry
{
    private readonly ConcurrentDictionary<string, RegistryEntry> _identities = new();

    /// <summary>
    /// Returns the number of registered identities.
    /// </summary>
    public int Count => _identities.Count;

    /// <summary>
    /// Registers an agent identity in the registry.
    /// </summary>
    /// <param name="identity">The identity to register.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="identity"/> is <c>null</c>.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an identity with the same DID is already registered.
    /// </exception>
    public void Register(AgentIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var entry = new RegistryEntry(identity);
        if (!_identities.TryAdd(identity.Did, entry))
        {
            throw new InvalidOperationException(
                $"An identity with DID '{identity.Did}' is already registered.");
        }
    }

    /// <summary>
    /// Retrieves an agent identity by its DID.
    /// </summary>
    /// <param name="did">The decentralised identifier to look up.</param>
    /// <returns>The registered <see cref="AgentIdentity"/>.</returns>
    /// <exception cref="KeyNotFoundException">
    /// Thrown when no identity with the specified DID is registered.
    /// </exception>
    public AgentIdentity Get(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);

        if (_identities.TryGetValue(did, out var entry))
        {
            return entry.Identity;
        }

        throw new KeyNotFoundException($"No identity registered with DID '{did}'.");
    }

    /// <summary>
    /// Revokes an agent identity by its DID.
    /// </summary>
    /// <param name="did">The DID of the identity to revoke.</param>
    /// <param name="reason">The reason for revocation.</param>
    /// <exception cref="KeyNotFoundException">
    /// Thrown when no identity with the specified DID is registered.
    /// </exception>
    public void Revoke(string did, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if (!_identities.TryGetValue(did, out var entry))
        {
            throw new KeyNotFoundException($"No identity registered with DID '{did}'.");
        }

        entry.Identity.Revoke();
        entry.RevocationReason = reason;
    }

    /// <summary>
    /// Returns all identities that are currently active.
    /// </summary>
    /// <returns>A read-only list of active agent identities.</returns>
    public IReadOnlyList<AgentIdentity> ListActive()
    {
        return _identities.Values
            .Where(e => e.Identity.IsActive())
            .Select(e => e.Identity)
            .ToList()
            .AsReadOnly();
    }

    /// <summary>
    /// Internal registry entry wrapping an identity with optional revocation metadata.
    /// </summary>
    private sealed class RegistryEntry
    {
        public AgentIdentity Identity { get; }
        public string? RevocationReason { get; set; }

        public RegistryEntry(AgentIdentity identity)
        {
            Identity = identity;
        }
    }
}
