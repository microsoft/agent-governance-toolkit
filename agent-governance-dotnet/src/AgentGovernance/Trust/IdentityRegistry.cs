// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

namespace AgentGovernance.Trust;

/// <summary>
/// A thread-safe registry for managing <see cref="AgentIdentity"/> instances.
/// Supports registration, lookup, sponsor indexing, trust checks, and cascade revocation.
/// </summary>
public sealed class IdentityRegistry
{
    private readonly ConcurrentDictionary<string, AgentIdentity> _identities = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _bySponsor = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _requireAttestation;

    /// <summary>
    /// Creates a new registry.
    /// </summary>
    public IdentityRegistry(bool requireAttestation = false)
    {
        _requireAttestation = requireAttestation;
    }

    /// <summary>
    /// Returns the number of registered identities.
    /// </summary>
    public int Count => _identities.Count;

    /// <summary>
    /// Registers an agent identity in the registry.
    /// </summary>
    public void Register(AgentIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (_requireAttestation && !identity.AttestationVerified)
        {
            throw new InvalidOperationException(
                $"Identity '{identity.Did}' cannot be registered until attestation is verified.");
        }

        if (!_identities.TryAdd(identity.Did, identity))
        {
            throw new InvalidOperationException(
                $"An identity with DID '{identity.Did}' is already registered.");
        }

        var sponsorIndex = _bySponsor.GetOrAdd(
            identity.SponsorEmail,
            _ => new ConcurrentDictionary<string, byte>(StringComparer.Ordinal));
        sponsorIndex.TryAdd(identity.Did, 0);
    }

    /// <summary>
    /// Retrieves an agent identity by its DID.
    /// </summary>
    public AgentIdentity Get(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        if (TryGet(did, out var identity) && identity is not null)
        {
            return identity;
        }

        throw new KeyNotFoundException($"No identity registered with DID '{did}'.");
    }

    /// <summary>
    /// Attempts to retrieve an identity without throwing.
    /// </summary>
    public bool TryGet(string did, out AgentIdentity? identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        return _identities.TryGetValue(AgentIdentity.NormalizeDid(did), out identity);
    }

    /// <summary>
    /// Returns all identities for the given sponsor.
    /// </summary>
    public IReadOnlyList<AgentIdentity> GetBySponsor(string sponsorEmail)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sponsorEmail);

        if (!_bySponsor.TryGetValue(sponsorEmail, out var dids))
        {
            return Array.Empty<AgentIdentity>();
        }

        return dids.Keys
            .Select(Get)
            .OrderBy(identity => identity.Did, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Returns whether the registry trusts a given DID.
    /// </summary>
    public bool IsTrusted(string did)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        return TryGet(did, out var identity)
            && identity is not null
            && identity.IsActive()
            && (!_requireAttestation || identity.AttestationVerified);
    }

    /// <summary>
    /// Revokes an identity and any delegated children registered beneath it.
    /// </summary>
    public void Revoke(string did, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        var identity = Get(did);
        identity.Revoke(reason);

        var children = _identities.Values
            .Where(candidate => string.Equals(candidate.ParentDid, identity.Did, StringComparison.Ordinal))
            .Select(candidate => candidate.Did)
            .ToList();

        foreach (var childDid in children)
        {
            Revoke(childDid, $"Parent revoked: {reason}");
        }
    }

    /// <summary>
    /// Returns all identities that are currently active.
    /// </summary>
    public IReadOnlyList<AgentIdentity> ListActive()
    {
        return _identities.Values
            .Where(identity => identity.IsActive())
            .OrderBy(identity => identity.Did, StringComparer.Ordinal)
            .ToList();
    }
}
