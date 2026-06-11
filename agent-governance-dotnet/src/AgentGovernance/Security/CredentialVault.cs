// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AgentGovernance.Security;

/// <summary>
/// Outcome of a credential resolution attempt.
/// </summary>
public enum CredentialDecision
{
    /// <summary>Allowed.</summary>
    Allow,

    /// <summary>Denied.</summary>
    Deny,
}

/// <summary>
/// Base error for credential vault operations.
/// </summary>
public class CredentialException : Exception
{
    /// <summary>Create a new <see cref="CredentialException"/>.</summary>
    public CredentialException(string message) : base(message) { }
}

/// <summary>
/// An internal credential entry. Never exposed to agents.
/// </summary>
public sealed record CredentialRecord(
    string Name,
    string Value,
    string CredType,
    int Version,
    double CreatedAt,
    double? RotatedAt
);

/// <summary>
/// Opaque handle an agent may reference. Holding a handle does NOT grant
/// access to the underlying value; resolution requires the vault, the
/// agent's DID, and an action capability binding.
/// </summary>
public sealed class CredentialHandle
{
    /// <summary>The handle's name.</summary>
    public string Name { get; }

    /// <summary>Create a new handle.</summary>
    public CredentialHandle(string name) { Name = name; }

    /// <summary>Return the <c>{{cred:NAME}}</c> placeholder for this handle.</summary>
    public string Placeholder() => $"{{{{cred:{Name}}}}}";

    /// <inheritdoc/>
    public override string ToString() => $"<CredentialHandle {Name}>";
}

/// <summary>
/// Per-agent capability binding. Maps action capabilities (e.g.
/// <c>github:read_issues</c>) to credential handle names.
/// </summary>
public sealed class CredentialProfile
{
    /// <summary>The agent's DID.</summary>
    public string AgentDid { get; }

    private readonly ReadOnlyDictionary<string, string> _bindings;

    /// <summary>The capability -&gt; handle bindings (read-only).</summary>
    public IReadOnlyDictionary<string, string> Bindings => _bindings;

    /// <summary>Create a profile.</summary>
    public CredentialProfile(string agentDid, IDictionary<string, string> bindings)
    {
        if (string.IsNullOrEmpty(agentDid))
        {
            throw new ArgumentException("agentDid must be non-empty", nameof(agentDid));
        }
        AgentDid = agentDid;
        _bindings = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(bindings));
    }

    /// <summary>Return the handle name bound to the action class, or null.</summary>
    public string? CapabilityFor(string actionClass)
    {
        return _bindings.TryGetValue(actionClass, out var v) ? v : null;
    }
}

/// <summary>
/// A single audit record. Contains the agent identity, handle name,
/// target service, action class, decision, and policy version. Does NOT
/// contain the resolved credential value.
/// </summary>
public sealed record VaultAuditEvent(
    double Timestamp,
    string AgentDid,
    string HandleName,
    string TargetService,
    string ActionClass,
    CredentialDecision Decision,
    string PolicyVersion,
    string Reason
);

/// <summary>
/// Deterministic deny output returned in place of a rendered payload.
/// Identical for missing / out-of-scope / policy-denied handles so agents
/// cannot probe vault contents via deny shape.
/// </summary>
public sealed record DenyReceipt(
    string Reason = CredentialVault.DenyReason,
    string ActionClass = "",
    string TargetService = "");

/// <summary>
/// Encrypted-at-rest credential store and scoped resolver.
/// </summary>
/// <remarks>
/// Persistence uses AES-256-GCM with a 12-byte random nonce prefixed to
/// the ciphertext. The wire format is not currently interoperable with
/// the Python SDK's Fernet format -- see tracking issue #2535.
/// </remarks>
public sealed class CredentialVault
{
    /// <summary>Stable string returned in audit/deny records when a request is refused.</summary>
    public const string DenyReason = "credential_denied";

    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private static readonly Regex NameRegex = new(
        "^[A-Za-z0-9_.\\-]{1,128}$", RegexOptions.Compiled);

    private readonly object _lock = new();
    private readonly Dictionary<string, CredentialRecord> _records = new();
    private readonly Dictionary<string, CredentialProfile> _profiles = new();
    private readonly List<VaultAuditEvent> _audit = new();
    private readonly string? _persistPath;
    private readonly byte[]? _key;
    private bool _loaded;

    /// <summary>Create an in-memory vault.</summary>
    public CredentialVault() { }

    /// <summary>Create a vault with encrypted-at-rest persistence.</summary>
    /// <param name="persistPath">Path to the encrypted vault file.</param>
    /// <param name="encryptionKey">32-byte AES-256-GCM key. Use <see cref="GenerateKey"/>.</param>
    public CredentialVault(string persistPath, byte[] encryptionKey)
    {
        if (string.IsNullOrEmpty(persistPath))
        {
            throw new ArgumentException("persistPath must be non-empty", nameof(persistPath));
        }
        if (encryptionKey is null || encryptionKey.Length != KeyLength)
        {
            throw new ArgumentException(
                $"encryptionKey must be exactly {KeyLength} bytes", nameof(encryptionKey));
        }
        _persistPath = persistPath;
        _key = (byte[])encryptionKey.Clone();
    }

    /// <summary>Generate a fresh AES-256-GCM key (32 random bytes).</summary>
    public static byte[] GenerateKey()
    {
        var k = new byte[KeyLength];
        RandomNumberGenerator.Fill(k);
        return k;
    }

    // -- Admin surface ------------------------------------------------------

    /// <summary>Store or replace a credential.</summary>
    public CredentialHandle Put(string name, string value, string credType = "secret")
    {
        if (!NameRegex.IsMatch(name ?? string.Empty))
        {
            throw new ArgumentException(
                "Credential name must match [A-Za-z0-9_.-]{1,128}", nameof(name));
        }
        lock (_lock)
        {
            EnsureLoaded();
            var now = NowSeconds();
            var rec = _records.TryGetValue(name!, out var existing)
                ? existing with
                {
                    Value = value,
                    Version = existing.Version + 1,
                    RotatedAt = now,
                }
                : new CredentialRecord(
                    Name: name!,
                    Value: value,
                    CredType: credType,
                    Version: 1,
                    CreatedAt: now,
                    RotatedAt: null);
            _records[name!] = rec;
            Flush();
        }
        return new CredentialHandle(name!);
    }

    /// <summary>Rotate a credential's value, preserving the handle name.</summary>
    public CredentialHandle Rotate(string name, string newValue)
    {
        lock (_lock)
        {
            EnsureLoaded();
            if (!_records.TryGetValue(name, out var old))
            {
                throw new KeyNotFoundException($"unknown credential: {name}");
            }
            _records[name] = old with
            {
                Value = newValue,
                Version = old.Version + 1,
                RotatedAt = NowSeconds(),
            };
            Flush();
        }
        return new CredentialHandle(name);
    }

    /// <summary>Delete a credential. Returns true if it existed.</summary>
    public bool Delete(string name)
    {
        lock (_lock)
        {
            EnsureLoaded();
            var present = _records.Remove(name);
            if (present) { Flush(); }
            return present;
        }
    }

    /// <summary>List all credential handle names.</summary>
    public IReadOnlyList<string> ListHandles()
    {
        lock (_lock)
        {
            EnsureLoaded();
            var names = _records.Keys.ToList();
            names.Sort(StringComparer.Ordinal);
            return names;
        }
    }

    /// <summary>Return non-secret metadata for a credential, or null.</summary>
    public IReadOnlyDictionary<string, object?>? GetMetadata(string name)
    {
        lock (_lock)
        {
            EnsureLoaded();
            if (!_records.TryGetValue(name, out var r)) return null;
            return new Dictionary<string, object?>
            {
                ["name"] = r.Name,
                ["credType"] = r.CredType,
                ["version"] = r.Version,
                ["createdAt"] = r.CreatedAt,
                ["rotatedAt"] = r.RotatedAt,
            };
        }
    }

    /// <summary>Register or replace a per-agent profile.</summary>
    public void RegisterProfile(CredentialProfile profile)
    {
        lock (_lock) { _profiles[profile.AgentDid] = profile; }
    }

    /// <summary>Revoke a profile by agent DID. Returns true if it existed.</summary>
    public bool RevokeProfile(string agentDid)
    {
        lock (_lock) { return _profiles.Remove(agentDid); }
    }

    // -- Resolver surface ---------------------------------------------------

    /// <summary>True iff the agent may use the handle for the action class.</summary>
    public bool CheckAccess(string agentDid, string handleName, string actionClass)
    {
        lock (_lock)
        {
            if (!_profiles.TryGetValue(agentDid, out var profile)) return false;
            var bound = profile.CapabilityFor(actionClass);
            if (bound is null || bound != handleName) return false;
            return _records.ContainsKey(handleName);
        }
    }

    /// <summary>
    /// Internal: resolve a credential value and emit an audit event.
    /// Use <see cref="CredentialInjector"/> rather than calling directly.
    /// </summary>
    internal (string? Value, VaultAuditEvent Event) ResolveInternal(
        string agentDid,
        string handleName,
        string actionClass,
        string targetService,
        string policyVersion)
    {
        lock (_lock)
        {
            var allowed = CheckAccessNoLock(agentDid, handleName, actionClass);
            if (allowed)
            {
                var value = _records[handleName].Value;
                var ev = new VaultAuditEvent(
                    Timestamp: NowSeconds(),
                    AgentDid: agentDid,
                    HandleName: handleName,
                    TargetService: targetService,
                    ActionClass: actionClass,
                    Decision: CredentialDecision.Allow,
                    PolicyVersion: policyVersion,
                    Reason: string.Empty);
                _audit.Add(ev);
                return (value, ev);
            }
            var denyEv = new VaultAuditEvent(
                Timestamp: NowSeconds(),
                AgentDid: agentDid,
                HandleName: handleName,
                TargetService: targetService,
                ActionClass: actionClass,
                Decision: CredentialDecision.Deny,
                PolicyVersion: policyVersion,
                Reason: DenyReason);
            _audit.Add(denyEv);
            return (null, denyEv);
        }
    }

    internal void RecordReject(VaultAuditEvent ev)
    {
        lock (_lock) { _audit.Add(ev); }
    }

    /// <summary>Immutable snapshot of audit events.</summary>
    public IReadOnlyList<VaultAuditEvent> AuditLog()
    {
        lock (_lock) { return _audit.ToList(); }
    }

    /// <summary>Clear all audit events.</summary>
    public void ClearAudit()
    {
        lock (_lock) { _audit.Clear(); }
    }

    // -- Internal helpers ---------------------------------------------------

    private bool CheckAccessNoLock(string agentDid, string handleName, string actionClass)
    {
        if (!_profiles.TryGetValue(agentDid, out var profile)) return false;
        var bound = profile.CapabilityFor(actionClass);
        if (bound is null || bound != handleName) return false;
        return _records.ContainsKey(handleName);
    }

    private static double NowSeconds() =>
        (DateTimeOffset.UtcNow - DateTimeOffset.UnixEpoch).TotalSeconds;

    private void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        if (_persistPath is null || _key is null) return;
        if (!File.Exists(_persistPath)) return;
        var blob = File.ReadAllBytes(_persistPath);
        if (blob.Length == 0) return;
        var plaintext = Decrypt(blob);
        var payload = JsonSerializer.Deserialize<PersistPayload>(plaintext);
        if (payload?.Records is null) return;
        foreach (var r in payload.Records)
        {
            _records[r.Name] = r;
        }
    }

    private void Flush()
    {
        if (_persistPath is null || _key is null) return;
        var payload = new PersistPayload(_records.Values.ToList());
        var json = JsonSerializer.SerializeToUtf8Bytes(payload);
        var blob = Encrypt(json);
        var tmp = _persistPath + ".tmp";
        var dir = Path.GetDirectoryName(_persistPath);
        if (!string.IsNullOrEmpty(dir)) { Directory.CreateDirectory(dir); }
        File.WriteAllBytes(tmp, blob);
        File.Move(tmp, _persistPath, overwrite: true);
    }

    private byte[] Encrypt(byte[] plaintext)
    {
        if (_key is null) throw new InvalidOperationException("no key");
        var nonce = new byte[NonceLength];
        RandomNumberGenerator.Fill(nonce);
        var ct = new byte[plaintext.Length];
        var tag = new byte[TagLength];
        using (var gcm = new AesGcm(_key, TagLength))
        {
            gcm.Encrypt(nonce, plaintext, ct, tag);
        }
        var output = new byte[NonceLength + ct.Length + TagLength];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceLength);
        Buffer.BlockCopy(ct, 0, output, NonceLength, ct.Length);
        Buffer.BlockCopy(tag, 0, output, NonceLength + ct.Length, TagLength);
        return output;
    }

    private byte[] Decrypt(byte[] blob)
    {
        if (_key is null) throw new InvalidOperationException("no key");
        if (blob.Length < NonceLength + TagLength)
        {
            throw new CredentialException("persisted vault is corrupt (too short)");
        }
        var nonce = new byte[NonceLength];
        var tag = new byte[TagLength];
        var ct = new byte[blob.Length - NonceLength - TagLength];
        Buffer.BlockCopy(blob, 0, nonce, 0, NonceLength);
        Buffer.BlockCopy(blob, NonceLength, ct, 0, ct.Length);
        Buffer.BlockCopy(blob, NonceLength + ct.Length, tag, 0, TagLength);
        var pt = new byte[ct.Length];
        using (var gcm = new AesGcm(_key, TagLength))
        {
            gcm.Decrypt(nonce, ct, tag, pt);
        }
        return pt;
    }

    private sealed record PersistPayload(List<CredentialRecord> Records);
}

/// <summary>Context passed to the workflow policy callback.</summary>
public sealed record InjectionContext(
    string AgentDid,
    string ActionClass,
    string TargetService,
    IReadOnlyList<string> RequestedHandles,
    string PolicyVersion);

/// <summary>Result returned by the workflow policy callback.</summary>
public sealed record PolicyOutcome(bool Allow, string Reason = "");

/// <summary>Outcome of an injection call.</summary>
public sealed record InjectionResult(
    bool Allowed,
    object Payload,
    DenyReceipt? DenyReceipt,
    IReadOnlyList<VaultAuditEvent> AuditEvents);

/// <summary>Options for an injection call.</summary>
public sealed class InjectionOptions
{
    /// <summary>The action class this call represents (e.g. <c>github:read_issues</c>).</summary>
    public required string ActionClass { get; init; }

    /// <summary>The downstream service this credential will be sent to.</summary>
    public required string TargetService { get; init; }

    /// <summary>
    /// Workflow-policy allowlist of handle names eligible for substitution
    /// on this call. Placeholders outside this set deny the whole call.
    /// </summary>
    public required IEnumerable<string> AllowedHandles { get; init; }

    /// <summary>Recorded in the audit log.</summary>
    public string PolicyVersion { get; init; } = "v0";

    /// <summary>
    /// Optional workflow-policy callback. Invoked BEFORE any vault read.
    /// </summary>
    public Func<InjectionContext, PolicyOutcome>? PolicyCheck { get; init; }
}

/// <summary>
/// Renders <c>{{cred:NAME}}</c> placeholders into HTTP headers, MCP tool
/// arguments, and environment variable payloads.
/// </summary>
/// <remarks>
/// The injector is the only component that ever holds resolved credential
/// values, and only long enough to render an outbound payload.
/// </remarks>
public sealed class CredentialInjector
{
    /// <summary>Regex matching the credential placeholder syntax <c>{{cred:NAME}}</c>.</summary>
    public static readonly Regex PlaceholderRegex = new(
        "\\{\\{\\s*cred:([A-Za-z0-9_.\\-]{1,128})\\s*\\}\\}", RegexOptions.Compiled);

    private readonly CredentialVault _vault;

    /// <summary>Create an injector backed by the given vault.</summary>
    public CredentialInjector(CredentialVault vault) { _vault = vault; }

    /// <summary>Inject placeholders in an HTTP header dictionary.</summary>
    public InjectionResult InjectHeaders(
        string agentDid,
        IDictionary<string, string> headers,
        InjectionOptions options) =>
        Inject(agentDid, new Dictionary<string, string>(headers), options);

    /// <summary>Inject placeholders in MCP tool arguments (nested dict/list/string).</summary>
    public InjectionResult InjectToolArgs(
        string agentDid,
        object args,
        InjectionOptions options) =>
        Inject(agentDid, args, options);

    /// <summary>Inject placeholders in a subprocess environment dictionary.</summary>
    public InjectionResult InjectEnv(
        string agentDid,
        IDictionary<string, string> env,
        InjectionOptions options) =>
        Inject(agentDid, new Dictionary<string, string>(env), options);

    private InjectionResult Inject(string agentDid, object payload, InjectionOptions options)
    {
        var allowlist = new HashSet<string>(options.AllowedHandles);
        var requested = CollectPlaceholders(payload);

        // 1. Reject anything outside the workflow-supplied allowlist.
        var outside = requested.Where(n => !allowlist.Contains(n)).ToList();
        if (outside.Count > 0)
        {
            var ev = new VaultAuditEvent(
                Timestamp: (DateTimeOffset.UtcNow - DateTimeOffset.UnixEpoch).TotalSeconds,
                AgentDid: agentDid,
                HandleName: outside[0],
                TargetService: options.TargetService,
                ActionClass: options.ActionClass,
                Decision: CredentialDecision.Deny,
                PolicyVersion: options.PolicyVersion,
                Reason: CredentialVault.DenyReason);
            _vault.RecordReject(ev);
            var deny = new DenyReceipt(
                Reason: CredentialVault.DenyReason,
                ActionClass: options.ActionClass,
                TargetService: options.TargetService);
            return new InjectionResult(false, deny, deny, new[] { ev });
        }

        // 2. Run policy BEFORE any vault read.
        if (options.PolicyCheck is not null)
        {
            var ctx = new InjectionContext(
                AgentDid: agentDid,
                ActionClass: options.ActionClass,
                TargetService: options.TargetService,
                RequestedHandles: requested.OrderBy(s => s, StringComparer.Ordinal).ToList(),
                PolicyVersion: options.PolicyVersion);
            var outcome = options.PolicyCheck(ctx);
            if (!outcome.Allow)
            {
                var ev = new VaultAuditEvent(
                    Timestamp: (DateTimeOffset.UtcNow - DateTimeOffset.UnixEpoch).TotalSeconds,
                    AgentDid: agentDid,
                    HandleName: requested.FirstOrDefault() ?? string.Empty,
                    TargetService: options.TargetService,
                    ActionClass: options.ActionClass,
                    Decision: CredentialDecision.Deny,
                    PolicyVersion: options.PolicyVersion,
                    Reason: CredentialVault.DenyReason);
                _vault.RecordReject(ev);
                var deny = new DenyReceipt(
                    Reason: CredentialVault.DenyReason,
                    ActionClass: options.ActionClass,
                    TargetService: options.TargetService);
                return new InjectionResult(false, deny, deny, new[] { ev });
            }
        }

        // 3. Resolve. Any single deny aborts the whole call.
        var resolved = new Dictionary<string, string>();
        var events = new List<VaultAuditEvent>();
        foreach (var name in requested)
        {
            var (value, ev) = _vault.ResolveInternal(
                agentDid, name, options.ActionClass, options.TargetService, options.PolicyVersion);
            events.Add(ev);
            if (value is null)
            {
                var deny = new DenyReceipt(
                    Reason: CredentialVault.DenyReason,
                    ActionClass: options.ActionClass,
                    TargetService: options.TargetService);
                return new InjectionResult(false, deny, deny, events);
            }
            resolved[name] = value;
        }

        var rendered = Substitute(payload, resolved);
        return new InjectionResult(true, rendered, null, events);
    }

    private static HashSet<string> CollectPlaceholders(object payload)
    {
        var found = new HashSet<string>();
        Walk(payload, s =>
        {
            foreach (Match m in PlaceholderRegex.Matches(s))
            {
                found.Add(m.Groups[1].Value);
            }
        });
        return found;
    }

    private static object Substitute(object payload, IReadOnlyDictionary<string, string> resolved)
    {
        return MapStrings(payload, s => PlaceholderRegex.Replace(s, m =>
            resolved.TryGetValue(m.Groups[1].Value, out var v) ? v : m.Value));
    }

    private static void Walk(object? payload, Action<string> visit)
    {
        switch (payload)
        {
            case null:
                return;
            case string s:
                visit(s);
                return;
            case IDictionary<string, string> ds:
                foreach (var kv in ds)
                {
                    visit(kv.Key);
                    visit(kv.Value);
                }
                return;
            case IDictionary<string, object?> d:
                foreach (var kv in d)
                {
                    visit(kv.Key);
                    Walk(kv.Value, visit);
                }
                return;
            case IEnumerable<object?> list:
                foreach (var item in list) Walk(item, visit);
                return;
        }
    }

    private static object MapStrings(object payload, Func<string, string> fn)
    {
        switch (payload)
        {
            case string s:
                return fn(s);
            case IDictionary<string, string> ds:
                {
                    var o = new Dictionary<string, string>(ds.Count);
                    foreach (var kv in ds) o[fn(kv.Key)] = fn(kv.Value);
                    return o;
                }
            case IDictionary<string, object?> d:
                {
                    var o = new Dictionary<string, object?>(d.Count);
                    foreach (var kv in d)
                    {
                        o[fn(kv.Key)] = kv.Value is null ? null : MapStrings(kv.Value, fn);
                    }
                    return o;
                }
            case IList<object?> list:
                {
                    var o = new List<object?>(list.Count);
                    foreach (var item in list)
                    {
                        o.Add(item is null ? null : MapStrings(item, fn));
                    }
                    return o;
                }
            default:
                return payload;
        }
    }
}

/// <summary>
/// Audit-log integrity helper.
/// </summary>
public static class CredentialAudit
{
    /// <summary>
    /// Stable HMAC-SHA256 digest of an audit-event sequence. Covers handle
    /// names and decisions but never references resolved credential values.
    /// </summary>
    public static string Digest(IEnumerable<VaultAuditEvent> events, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        using var buf = new MemoryStream();
        foreach (var json in events.Select(ev => JsonSerializer.SerializeToUtf8Bytes(new
        {
            timestamp = ev.Timestamp,
            agentDid = ev.AgentDid,
            handleName = ev.HandleName,
            targetService = ev.TargetService,
            actionClass = ev.ActionClass,
            decision = ev.Decision.ToString().ToLowerInvariant(),
            policyVersion = ev.PolicyVersion,
            reason = ev.Reason,
        })))
        {
            buf.Write(json, 0, json.Length);
            buf.WriteByte(0x1f);
        }
        var digest = hmac.ComputeHash(buf.ToArray());
        var sb = new StringBuilder(digest.Length * 2);
        foreach (var b in digest) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
