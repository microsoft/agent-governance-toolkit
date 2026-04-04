// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentGovernance.Mcp.Abstractions;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Signing algorithm used by <see cref="McpMessageSigner"/>.
/// </summary>
public enum SigningAlgorithm
{
    /// <summary>HMAC-SHA256 symmetric signing (available on all .NET versions).</summary>
    HmacSha256,

#if NET10_0_OR_GREATER
    /// <summary>ML-DSA-65 post-quantum asymmetric signing (requires .NET 10+). NIST FIPS 204.</summary>
    MLDsa65,
#endif
}

/// <summary>
/// Signs and verifies MCP JSON-RPC messages for integrity and replay protection.
/// Implements OWASP MCP Security Cheat Sheet §7: Message-Level Integrity and Replay Protection.
/// <para>
/// On .NET 8: Uses HMAC-SHA256 with a shared secret for message authentication.
/// On .NET 10+: Optionally uses ML-DSA-65 (NIST FIPS 204) post-quantum asymmetric signing
/// for non-repudiation and quantum resistance.
/// Each signed message includes a nonce (GUID) and timestamp. Messages with duplicate nonces
/// or timestamps outside the replay window are rejected. Fail-closed on verification failure.
/// </para>
/// </summary>
public sealed class McpMessageSigner : IDisposable
{
    private readonly byte[] _signingKey;
    private readonly IMcpNonceStore _nonceStore;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _trackedNonces = new(StringComparer.Ordinal);
    private readonly SigningAlgorithm _algorithm;
    private readonly TimeProvider _timeProvider;

#if NET10_0_OR_GREATER
    private readonly MLDsa? _mlDsa;
#endif

    /// <summary>Replay window duration. Messages older than this are rejected. Defaults to 5 minutes.</summary>
    public TimeSpan ReplayWindow { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How often to clean expired nonces from cache. Defaults to 10 minutes.</summary>
    public TimeSpan NonceCacheCleanupInterval { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Maximum nonces to cache. Oldest are evicted when exceeded. Defaults to 10,000.</summary>
    public int MaxNonceCacheSize { get; init; } = 10_000;

    /// <summary>
    /// Optional logger for recording signature verification events.
    /// When <c>null</c>, no logging occurs — the signer operates silently.
    /// </summary>
    public ILogger<McpMessageSigner>? Logger { get; set; }

    /// <summary>The signing algorithm in use.</summary>
    public SigningAlgorithm Algorithm => _algorithm;

    private DateTimeOffset _lastCleanup;

    /// <summary>
    /// Initializes a new message signer with the given shared secret (HMAC-SHA256).
    /// </summary>
    /// <param name="signingKey">Shared secret key (minimum 16 bytes, 32 recommended).</param>
    /// <param name="nonceStore">The nonce store used for replay protection.</param>
    /// <param name="timeProvider">The clock used for timestamps and replay-window checks.</param>
    public McpMessageSigner(byte[] signingKey, IMcpNonceStore? nonceStore = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        if (signingKey.Length < 16)
            throw new ArgumentException("Signing key must be at least 16 bytes.", nameof(signingKey));
        _signingKey = signingKey;
        _nonceStore = nonceStore ?? new InMemoryMcpNonceStore();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _algorithm = SigningAlgorithm.HmacSha256;
        _lastCleanup = _timeProvider.GetUtcNow();
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Initializes a new message signer using ML-DSA-65 post-quantum asymmetric signing (.NET 10+).
    /// The ML-DSA key instance is owned by this signer and will be disposed when the signer is disposed.
    /// </summary>
    /// <param name="mlDsaKey">An ML-DSA key (private key for signing, public-only for verification).</param>
    /// <param name="nonceStore">The nonce store used for replay protection.</param>
    /// <param name="timeProvider">The clock used for timestamps and replay-window checks.</param>
    public McpMessageSigner(MLDsa mlDsaKey, IMcpNonceStore? nonceStore = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(mlDsaKey);
        _mlDsa = mlDsaKey;
        _signingKey = Array.Empty<byte>();
        _nonceStore = nonceStore ?? new InMemoryMcpNonceStore();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _algorithm = SigningAlgorithm.MLDsa65;
        _lastCleanup = _timeProvider.GetUtcNow();
    }

    /// <summary>
    /// Generates a new ML-DSA-65 key pair for post-quantum message signing (.NET 10+).
    /// </summary>
    /// <returns>A new <see cref="McpMessageSigner"/> initialized with a fresh ML-DSA-65 key pair.</returns>
    public static McpMessageSigner CreateMLDsa()
    {
        return new McpMessageSigner(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65));
    }

    /// <summary>
    /// Creates a verification-only signer from an ML-DSA-65 public key (.NET 10+).
    /// </summary>
    /// <param name="publicKey">The ML-DSA-65 public key bytes.</param>
    /// <returns>A new <see cref="McpMessageSigner"/> that can verify but not sign messages.</returns>
    public static McpMessageSigner CreateMLDsaVerifier(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return new McpMessageSigner(MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey));
    }

    /// <summary>
    /// Exports the ML-DSA-65 public key for sharing with verification peers (.NET 10+).
    /// </summary>
    /// <returns>The public key bytes, or null if not using ML-DSA.</returns>
    public byte[]? ExportMLDsaPublicKey()
    {
        return _mlDsa?.ExportMLDsaPublicKey();
    }
#endif

    /// <summary>
    /// Creates a signer from a base64-encoded key string (HMAC-SHA256).
    /// </summary>
    /// <param name="base64Key">Base64-encoded shared secret key.</param>
    /// <returns>A new <see cref="McpMessageSigner"/> initialized with the decoded key.</returns>
    public static McpMessageSigner FromBase64Key(string base64Key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Key);
        return new McpMessageSigner(Convert.FromBase64String(base64Key));
    }

    /// <summary>
    /// Generates a new random 256-bit signing key (for HMAC-SHA256).
    /// </summary>
    /// <returns>A 32-byte cryptographically random key.</returns>
    public static byte[] GenerateKey()
    {
        return RandomNumberGenerator.GetBytes(32);
    }

    /// <summary>
    /// Signs a JSON-RPC message payload, wrapping it in a signed envelope with nonce and timestamp.
    /// </summary>
    /// <param name="payload">The JSON-RPC message content (serialized as JSON string).</param>
    /// <param name="senderId">Identity of the sender (for attribution).</param>
    /// <returns>A signed envelope containing the payload, nonce, timestamp, senderId, and signature.</returns>
    public McpSignedEnvelope SignMessage(string payload, string? senderId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);

        var nonce = Guid.NewGuid().ToString("N");
        var timestamp = _timeProvider.GetUtcNow();

        // Canonical string to sign: nonce|timestamp_unix_ms|senderId|payload
        var canonicalString = BuildCanonicalString(nonce, timestamp, senderId, payload);
        var signature = ComputeSignature(canonicalString);

        return new McpSignedEnvelope
        {
            Payload = payload,
            Nonce = nonce,
            Timestamp = timestamp,
            SenderId = senderId,
            Signature = signature,
            Algorithm = _algorithm.ToString()
        };
    }

    /// <summary>
    /// Verifies a signed envelope's integrity and replay protection.
    /// </summary>
    /// <param name="envelope">The signed envelope to verify.</param>
    /// <returns>A verification result indicating success or the reason for failure.</returns>
    public McpVerificationResult VerifyMessage(McpSignedEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        try
        {
            // 1. Check timestamp within replay window
            var age = _timeProvider.GetUtcNow() - envelope.Timestamp;
            if (age > ReplayWindow || age < -ReplayWindow)
                return McpVerificationResult.Failed("Message timestamp outside replay window.");

            // 2. Verify signature FIRST (before caching nonce, to prevent cache pollution)
            var canonicalString = BuildCanonicalString(
                envelope.Nonce, envelope.Timestamp, envelope.SenderId, envelope.Payload);

            if (!VerifySignature(canonicalString, envelope.Signature))
            {
                Logger?.LogWarning("MCP message signature verification failed");
                return McpVerificationResult.Failed("Invalid signature.");
            }

            // 3. Check nonce not seen before (only after signature is valid)
            if (!_nonceStore.AddAsync(envelope.Nonce, envelope.Timestamp).GetAwaiter().GetResult())
            {
                Logger?.LogWarning("MCP replay attack detected: duplicate nonce {Nonce}", envelope.Nonce);
                return McpVerificationResult.Failed("Duplicate nonce (replay detected).");
            }

            _trackedNonces[envelope.Nonce] = envelope.Timestamp;

            // 3b. Evict oldest nonces if cache exceeds max size
            EnforceNonceCacheSize();

            // 4. Periodic nonce cache cleanup
            MaybeCleanupNonces();

            return McpVerificationResult.Success(envelope.Payload, envelope.SenderId);
        }
        catch (Exception ex)
        {
            // Fail-closed
            return McpVerificationResult.Failed($"Verification error (fail-closed): {ex.Message}");
        }
    }

    /// <summary>
    /// Gets the number of cached nonces.
    /// </summary>
    public int CachedNonceCount => _trackedNonces.Count;

    /// <summary>
    /// Manually triggers nonce cache cleanup (removes entries outside the replay window).
    /// </summary>
    /// <returns>The number of expired nonces removed.</returns>
    public int CleanupNonceCache()
    {
        var cutoff = _timeProvider.GetUtcNow().Subtract(ReplayWindow);
        var removed = _nonceStore.CleanupAsync(cutoff).GetAwaiter().GetResult();

        foreach (var nonce in _trackedNonces.Where(kv => kv.Value <= cutoff).Select(kv => kv.Key).ToList())
        {
            _trackedNonces.TryRemove(nonce, out _);
        }

        _lastCleanup = _timeProvider.GetUtcNow();
        return removed;
    }

    /// <inheritdoc />
    public void Dispose()
    {
#if NET10_0_OR_GREATER
        _mlDsa?.Dispose();
#endif
    }

    private string BuildCanonicalString(string nonce, DateTimeOffset timestamp, string? senderId, string payload)
    {
        var unixMs = timestamp.ToUnixTimeMilliseconds();
        return $"{nonce}|{unixMs}|{senderId ?? ""}|{payload}";
    }

    private string ComputeSignature(string data)
    {
#if NET10_0_OR_GREATER
        if (_algorithm == SigningAlgorithm.MLDsa65 && _mlDsa is not null)
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var signature = _mlDsa.SignData(dataBytes, Array.Empty<byte>());
            return Convert.ToBase64String(signature);
        }
#endif
        return ComputeHmac(data);
    }

    private bool VerifySignature(string data, string signature)
    {
#if NET10_0_OR_GREATER
        if (_algorithm == SigningAlgorithm.MLDsa65 && _mlDsa is not null)
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var signatureBytes = Convert.FromBase64String(signature);
            return _mlDsa.VerifyData(dataBytes, signatureBytes, Array.Empty<byte>());
        }
#endif
        // HMAC: constant-time comparison to prevent timing attacks
        var expectedSignature = ComputeHmac(data);
        return CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(signature),
            Convert.FromBase64String(expectedSignature));
    }

    private string ComputeHmac(string data)
    {
        using var hmac = new HMACSHA256(_signingKey);
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash);
    }

    private void MaybeCleanupNonces()
    {
        if (_timeProvider.GetUtcNow() - _lastCleanup > NonceCacheCleanupInterval)
            CleanupNonceCache();
    }

    private void EnforceNonceCacheSize()
    {
        if (_trackedNonces.Count > MaxNonceCacheSize)
        {
            var toRemove = _trackedNonces
                .OrderBy(kv => kv.Value)
                .Take(_trackedNonces.Count - MaxNonceCacheSize)
                .ToList();

            if (toRemove.Count == 0)
            {
                return;
            }

            var cutoff = toRemove[^1].Value;
            _nonceStore.CleanupAsync(cutoff).GetAwaiter().GetResult();

            foreach (var nonce in _trackedNonces.Where(kv => kv.Value <= cutoff).Select(kv => kv.Key).ToList())
            {
                _trackedNonces.TryRemove(nonce, out _);
            }

            Logger?.LogDebug("MCP nonce cache eviction: removed {Count} entries", toRemove.Count);
        }
    }
}

/// <summary>
/// A signed MCP message envelope containing the payload, metadata, and HMAC signature.
/// </summary>
public sealed class McpSignedEnvelope
{
    /// <summary>The JSON-RPC message payload.</summary>
    public required string Payload { get; init; }

    /// <summary>Unique nonce (GUID) for replay protection.</summary>
    public required string Nonce { get; init; }

    /// <summary>Timestamp when the message was signed.</summary>
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Identity of the sender (certificate fingerprint, DID, etc.).</summary>
    public string? SenderId { get; init; }

    /// <summary>HMAC-SHA256 or ML-DSA-65 signature (base64-encoded).</summary>
    public required string Signature { get; init; }

    /// <summary>Algorithm used to produce the signature (e.g., "HmacSha256" or "MLDsa65").</summary>
    public string? Algorithm { get; init; }
}

/// <summary>
/// Result of verifying an MCP signed envelope.
/// </summary>
public sealed class McpVerificationResult
{
    /// <summary>Whether verification succeeded.</summary>
    public bool IsValid { get; init; }

    /// <summary>The verified payload (only set if valid).</summary>
    public string? Payload { get; init; }

    /// <summary>Sender identity from the envelope (only set if valid).</summary>
    public string? SenderId { get; init; }

    /// <summary>Failure reason (only set if invalid).</summary>
    public string? FailureReason { get; init; }

    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <param name="payload">The verified payload.</param>
    /// <param name="senderId">The sender identity from the envelope.</param>
    /// <returns>A successful <see cref="McpVerificationResult"/>.</returns>
    public static McpVerificationResult Success(string payload, string? senderId) =>
        new() { IsValid = true, Payload = payload, SenderId = senderId };

    /// <summary>
    /// Creates a failed verification result.
    /// </summary>
    /// <param name="reason">Description of why verification failed.</param>
    /// <returns>A failed <see cref="McpVerificationResult"/>.</returns>
    public static McpVerificationResult Failed(string reason) =>
        new() { IsValid = false, FailureReason = reason };
}
