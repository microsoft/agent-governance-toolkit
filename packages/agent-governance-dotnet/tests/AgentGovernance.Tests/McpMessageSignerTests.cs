// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Reflection;
using System.Security.Cryptography;
using AgentGovernance.Mcp;
using AgentGovernance.Mcp.Abstractions;
using Xunit;

namespace AgentGovernance.Tests;

#if NET10_0_OR_GREATER
internal sealed class RequiresMldsaSupportFactAttribute : FactAttribute
{
    public RequiresMldsaSupportFactAttribute()
    {
        if (!IsMldsaSupported())
        {
            Skip = "Requires .NET 10+ with ML-DSA support.";
        }
    }

    private static bool IsMldsaSupported()
    {
        try
        {
            using var signer = McpMessageSigner.CreateMLDsa();
            return signer.ExportMLDsaPublicKey() is { Length: > 0 };
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
#endif

public class McpMessageSignerTests
{
    private static byte[] CreateTestKey(int length = 32) =>
        RandomNumberGenerator.GetBytes(length);

    private static McpMessageSigner CreateSigner(byte[]? key = null, ManualTimeProvider? timeProvider = null) =>
        new(key ?? CreateTestKey(), new InMemoryMcpNonceStore(), timeProvider);

    // ── Signing ─────────────────────────────────────────────────────────

    [Fact]
    public void SignMessage_ValidPayload_ReturnsEnvelope()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var signer = CreateSigner(timeProvider: timeProvider);
        var payload = """{"jsonrpc":"2.0","method":"tools/call","id":1}""";

        var envelope = signer.SignMessage(payload);

        Assert.NotNull(envelope);
        Assert.Equal(payload, envelope.Payload);
        Assert.NotNull(envelope.Nonce);
        Assert.NotEmpty(envelope.Nonce);
        Assert.NotNull(envelope.Signature);
        Assert.NotEmpty(envelope.Signature);
        Assert.Equal(timeProvider.GetUtcNow(), envelope.Timestamp);
    }

    [Fact]
    public void SignMessage_WithSenderId_IncludesInEnvelope()
    {
        var signer = CreateSigner();
        var payload = """{"jsonrpc":"2.0","method":"ping","id":2}""";

        var envelope = signer.SignMessage(payload, senderId: "did:mesh:agent-42");

        Assert.Equal("did:mesh:agent-42", envelope.SenderId);
        Assert.NotNull(envelope.Signature);
    }

    [Fact]
    public void SignMessage_NullPayload_Throws()
    {
        var signer = CreateSigner();

        Assert.Throws<ArgumentNullException>(() => signer.SignMessage(null!));
    }

    [Fact]
    public void SignMessage_EmptyPayload_Throws()
    {
        var signer = CreateSigner();

        Assert.Throws<ArgumentException>(() => signer.SignMessage(""));
    }

    [Fact]
    public void SignMessage_WhitespacePayload_Throws()
    {
        var signer = CreateSigner();

        Assert.Throws<ArgumentException>(() => signer.SignMessage("   "));
    }

    // ── Verification (round-trip) ───────────────────────────────────────

    [Fact]
    public void VerifyMessage_ValidEnvelope_ReturnsSuccess()
    {
        var signer = CreateSigner();
        var payload = """{"jsonrpc":"2.0","method":"tools/call","id":1}""";

        var envelope = signer.SignMessage(payload, senderId: "test-agent");
        var result = signer.VerifyMessage(envelope);

        Assert.True(result.IsValid);
        Assert.Equal(payload, result.Payload);
        Assert.Equal("test-agent", result.SenderId);
        Assert.Null(result.FailureReason);
    }

    [Fact]
    public void VerifyMessage_NoSenderId_ReturnsSuccess()
    {
        var signer = CreateSigner();
        var payload = """{"jsonrpc":"2.0","method":"ping","id":1}""";

        var envelope = signer.SignMessage(payload);
        var result = signer.VerifyMessage(envelope);

        Assert.True(result.IsValid);
        Assert.Equal(payload, result.Payload);
        Assert.Null(result.SenderId);
    }

    // ── Tamper detection ────────────────────────────────────────────────

    [Fact]
    public void VerifyMessage_TamperedPayload_Fails()
    {
        var signer = CreateSigner();
        var envelope = signer.SignMessage("""{"method":"safe"}""");

        // Tamper with the payload
        var tampered = new McpSignedEnvelope
        {
            Payload = """{"method":"evil"}""",
            Nonce = envelope.Nonce,
            Timestamp = envelope.Timestamp,
            SenderId = envelope.SenderId,
            Signature = envelope.Signature
        };

        var result = signer.VerifyMessage(tampered);

        Assert.False(result.IsValid);
        Assert.Contains("Invalid signature", result.FailureReason);
    }

    [Fact]
    public void VerifyMessage_TamperedSignature_Fails()
    {
        var signer = CreateSigner();
        var envelope = signer.SignMessage("""{"method":"test"}""");

        // Generate a valid-looking but wrong base64 signature
        var wrongSig = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var tampered = new McpSignedEnvelope
        {
            Payload = envelope.Payload,
            Nonce = envelope.Nonce,
            Timestamp = envelope.Timestamp,
            SenderId = envelope.SenderId,
            Signature = wrongSig
        };

        var result = signer.VerifyMessage(tampered);

        Assert.False(result.IsValid);
        Assert.Contains("Invalid signature", result.FailureReason);
    }

    [Fact]
    public void VerifyMessage_WrongKey_Fails()
    {
        var signer1 = CreateSigner(CreateTestKey());
        var signer2 = CreateSigner(CreateTestKey());

        var envelope = signer1.SignMessage("""{"method":"test"}""");
        var result = signer2.VerifyMessage(envelope);

        Assert.False(result.IsValid);
        Assert.Contains("Invalid signature", result.FailureReason);
    }

    // ── Replay protection ───────────────────────────────────────────────

    [Fact]
    public void VerifyMessage_ReplayedMessage_Fails()
    {
        var signer = CreateSigner();
        var envelope = signer.SignMessage("""{"method":"test"}""");

        // First verification succeeds
        var first = signer.VerifyMessage(envelope);
        Assert.True(first.IsValid);

        // Second verification (replay) fails
        var second = signer.VerifyMessage(envelope);
        Assert.False(second.IsValid);
        Assert.Contains("Duplicate nonce", second.FailureReason);
    }

    [Fact]
    public void VerifyMessage_ExpiredTimestamp_Fails()
    {
        var key = CreateTestKey();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var signer = new McpMessageSigner(key, new InMemoryMcpNonceStore(), timeProvider)
        {
            ReplayWindow = TimeSpan.FromSeconds(5)
        };

        var payload = """{"method":"old"}""";
        var expiredEnvelope = signer.SignMessage(payload);
        timeProvider.Advance(TimeSpan.FromMinutes(10));

        var result = signer.VerifyMessage(expiredEnvelope);

        Assert.False(result.IsValid);
        Assert.Contains("replay window", result.FailureReason);
    }

    [Fact]
    public void VerifyMessage_FutureTimestamp_Fails()
    {
        var key = CreateTestKey();
        var signer = new McpMessageSigner(key)
        {
            ReplayWindow = TimeSpan.FromSeconds(5)
        };

        // Create an envelope with a future timestamp
        var payload = """{"method":"future"}""";
        var futureTimestamp = DateTimeOffset.UtcNow.AddMinutes(10);
        var nonce = Guid.NewGuid().ToString("N");
        var canonicalString = $"{nonce}|{futureTimestamp.ToUnixTimeMilliseconds()}||{payload}";
        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(canonicalString));
        var signature = Convert.ToBase64String(hash);

        var futureEnvelope = new McpSignedEnvelope
        {
            Payload = payload,
            Nonce = nonce,
            Timestamp = futureTimestamp,
            Signature = signature
        };

        var result = signer.VerifyMessage(futureEnvelope);

        Assert.False(result.IsValid);
        Assert.Contains("replay window", result.FailureReason);
    }

    // ── Constructor validation ──────────────────────────────────────────

    [Fact]
    public void Constructor_NullKey_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new McpMessageSigner((byte[])null!));
    }

    [Fact]
    public void Constructor_ShortKey_Throws()
    {
        var shortKey = new byte[16];

        var ex = Assert.Throws<ArgumentException>(() => new McpMessageSigner(shortKey));
        Assert.Contains("at least 32 bytes", ex.Message);
    }

    [Fact]
    public void Constructor_MinimumKeyLength_Works()
    {
        var key = CreateTestKey(32);
        var signer = new McpMessageSigner(key);

        var envelope = signer.SignMessage("""{"ok":true}""");
        var result = signer.VerifyMessage(envelope);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void VerifyMessage_NonceStoreFailure_DoesNotLeakExceptionDetails()
    {
        var signer = new McpMessageSigner(
            CreateTestKey(),
            new ThrowingNonceStore(),
            new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z")));
        var envelope = signer.SignMessage("""{"ok":true}""");

        var result = signer.VerifyMessage(envelope);

        Assert.False(result.IsValid);
        Assert.Equal("Verification error (fail-closed).", result.FailureReason);
    }

    // ── Factory methods ─────────────────────────────────────────────────

    [Fact]
    public void FromBase64Key_ValidKey_Works()
    {
        var key = CreateTestKey();
        var base64 = Convert.ToBase64String(key);

        var signer = McpMessageSigner.FromBase64Key(base64);

        var envelope = signer.SignMessage("""{"ok":true}""");
        var result = signer.VerifyMessage(envelope);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void FromBase64Key_NullOrEmpty_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => McpMessageSigner.FromBase64Key(null!));
        Assert.Throws<ArgumentException>(() => McpMessageSigner.FromBase64Key(""));
        Assert.Throws<ArgumentException>(() => McpMessageSigner.FromBase64Key("   "));
    }

    [Fact]
    public void GenerateKey_Returns32Bytes()
    {
        var key = McpMessageSigner.GenerateKey();

        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void GenerateKey_ReturnsDifferentKeysEachTime()
    {
        var key1 = McpMessageSigner.GenerateKey();
        var key2 = McpMessageSigner.GenerateKey();

        Assert.False(key1.SequenceEqual(key2));
    }

    // ── Nonce cache management ──────────────────────────────────────────

    [Fact]
    public void CleanupNonceCache_RemovesExpired()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.Parse("2024-01-01T00:00:00Z"));
        var signer = new McpMessageSigner(CreateTestKey(), new InMemoryMcpNonceStore(), timeProvider)
        {
            // Tiny replay window so entries expire immediately for testing
            ReplayWindow = TimeSpan.FromMilliseconds(1)
        };

        // Sign and verify several messages to populate the nonce cache
        for (int i = 0; i < 5; i++)
        {
            var env = signer.SignMessage($$$"""{"id":{{{i}}}}""");
            signer.VerifyMessage(env);
        }

        Assert.Equal(5, signer.CachedNonceCount);

        timeProvider.Advance(TimeSpan.FromMilliseconds(50));

        var removed = signer.CleanupNonceCache();

        Assert.Equal(5, removed);
        Assert.Equal(0, signer.CachedNonceCount);
    }

    [Fact]
    public void CachedNonceCount_TracksVerifiedMessages()
    {
        var signer = CreateSigner();

        Assert.Equal(0, signer.CachedNonceCount);

        var e1 = signer.SignMessage("""{"id":1}""");
        signer.VerifyMessage(e1);
        Assert.Equal(1, signer.CachedNonceCount);

        var e2 = signer.SignMessage("""{"id":2}""");
        signer.VerifyMessage(e2);
        Assert.Equal(2, signer.CachedNonceCount);
    }

    // ── Constant-time comparison ────────────────────────────────────────

    [Fact]
    public void VerifyMessage_ConstantTimeComparison_UsesFixedTimeEquals()
    {
        // Verify via source code inspection that the implementation uses
        // CryptographicOperations.FixedTimeEquals. We read the source file
        // and confirm the method is present in the VerifyMessage code path.
        var sourceFile = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "AgentGovernance", "Mcp", "McpMessageSigner.cs");

        // If source is available, verify the code uses FixedTimeEquals
        if (File.Exists(sourceFile))
        {
            var source = File.ReadAllText(sourceFile);
            Assert.Contains("CryptographicOperations.FixedTimeEquals", source);
        }

        // Additionally, verify the signer type has the VerifyMessage method
        // that returns McpVerificationResult (structural verification)
        var method = typeof(McpMessageSigner).GetMethod("VerifyMessage");
        Assert.NotNull(method);
        Assert.Equal(typeof(McpVerificationResult), method!.ReturnType);

        // Functional proof: a single-byte-off signature still fails
        // (timing attacks exploit early-exit comparisons, FixedTimeEquals prevents that)
        var key = CreateTestKey();
        var signer = new McpMessageSigner(key);
        var envelope = signer.SignMessage("""{"method":"test"}""");

        var sigBytes = Convert.FromBase64String(envelope.Signature);
        sigBytes[0] ^= 0x01; // Flip one bit
        var tampered = new McpSignedEnvelope
        {
            Payload = envelope.Payload,
            Nonce = envelope.Nonce,
            Timestamp = envelope.Timestamp,
            SenderId = envelope.SenderId,
            Signature = Convert.ToBase64String(sigBytes)
        };

        var result = signer.VerifyMessage(tampered);
        Assert.False(result.IsValid);
        Assert.Contains("Invalid signature", result.FailureReason);
    }

    // ── Fail-closed behavior ────────────────────────────────────────────

    [Fact]
    public void VerifyMessage_ExceptionInVerification_FailsClosed()
    {
        var signer = CreateSigner();

        // Create an envelope with a malformed (non-base64) signature to trigger
        // an exception in Convert.FromBase64String during verification
        var envelope = new McpSignedEnvelope
        {
            Payload = """{"method":"test"}""",
            Nonce = Guid.NewGuid().ToString("N"),
            Timestamp = DateTimeOffset.UtcNow,
            Signature = "not-valid-base64!!!"
        };

        var result = signer.VerifyMessage(envelope);

        Assert.False(result.IsValid);
        Assert.NotNull(result.FailureReason);
        Assert.Contains("fail-closed", result.FailureReason);
    }

    [Fact]
    public void VerifyMessage_NullEnvelope_Throws()
    {
        var signer = CreateSigner();

        Assert.Throws<ArgumentNullException>(() => signer.VerifyMessage(null!));
    }

    // ── Deterministic signing ───────────────────────────────────────────

    [Fact]
    public void SignMessage_SameKeySamePayload_ProducesDifferentEnvelopes()
    {
        var signer = CreateSigner();
        var payload = """{"method":"test"}""";

        var e1 = signer.SignMessage(payload);
        var e2 = signer.SignMessage(payload);

        // Different nonces → different signatures (non-deterministic)
        Assert.NotEqual(e1.Nonce, e2.Nonce);
        Assert.NotEqual(e1.Signature, e2.Signature);
    }

    // ── Nonce cache size cap ─────────────────────────────────────────────

    [Fact]
    public void NonceCacheSize_ExceedsMax_EvictsOldest()
    {
        var key = McpMessageSigner.GenerateKey();
        var signer = new McpMessageSigner(key) { MaxNonceCacheSize = 5 };

        for (int i = 0; i < 10; i++)
        {
            var envelope = signer.SignMessage($"{{\"id\":{i}}}");
            signer.VerifyMessage(envelope);
        }

        Assert.True(signer.CachedNonceCount <= 5);
    }

    // ── Algorithm property ──────────────────────────────────────────────

    [Fact]
    public void HmacSigner_HasCorrectAlgorithm()
    {
        var signer = CreateSigner();
        Assert.Equal(SigningAlgorithm.HmacSha256, signer.Algorithm);
    }

    [Fact]
    public void SignMessage_IncludesAlgorithmInEnvelope()
    {
        var signer = CreateSigner();
        var envelope = signer.SignMessage("""{"id":1}""");
        Assert.Equal("HmacSha256", envelope.Algorithm);
    }

#if NET10_0_OR_GREATER
    // ── ML-DSA-65 post-quantum (.NET 10+) ───────────────────────────────

    [RequiresMldsaSupportFact]
    public void CreateMLDsa_ReturnsSignerWithMLDsa65Algorithm()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        Assert.Equal(SigningAlgorithm.MLDsa65, signer.Algorithm);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_SignAndVerify_RoundTrip()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        var payload = """{"jsonrpc":"2.0","method":"tools/call","id":1}""";

        var envelope = signer.SignMessage(payload, "agent:pq-test");
        var result = signer.VerifyMessage(envelope);

        Assert.True(result.IsValid);
        Assert.Equal(payload, result.Payload);
        Assert.Equal("agent:pq-test", result.SenderId);
        Assert.Equal("MLDsa65", envelope.Algorithm);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_TamperedPayload_FailsVerification()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        var envelope = signer.SignMessage("""{"method":"tools/call"}""");

        var tampered = new McpSignedEnvelope
        {
            Payload = """{"method":"tools/call","INJECTED":true}""",
            Nonce = Guid.NewGuid().ToString("N"), // new nonce to avoid replay detection
            Timestamp = envelope.Timestamp,
            SenderId = envelope.SenderId,
            Signature = envelope.Signature,
            Algorithm = envelope.Algorithm
        };

        var result = signer.VerifyMessage(tampered);
        Assert.False(result.IsValid);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_DifferentSigner_FailsVerification()
    {
        using var signer1 = McpMessageSigner.CreateMLDsa();
        using var signer2 = McpMessageSigner.CreateMLDsa();

        var envelope = signer1.SignMessage("""{"id":1}""");
        var result = signer2.VerifyMessage(envelope);

        Assert.False(result.IsValid);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_ReplayDetection_Works()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        var envelope = signer.SignMessage("""{"id":1}""");

        var first = signer.VerifyMessage(envelope);
        Assert.True(first.IsValid);

        var replay = signer.VerifyMessage(envelope);
        Assert.False(replay.IsValid);
        Assert.Contains("replay", replay.FailureReason, StringComparison.OrdinalIgnoreCase);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_ExportPublicKey_ReturnsBytes()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        var pubKey = signer.ExportMLDsaPublicKey();

        Assert.NotNull(pubKey);
        Assert.Equal(1952, pubKey.Length); // ML-DSA-65 public key size
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_VerifierFromPublicKey_CanVerify()
    {
        using var signer = McpMessageSigner.CreateMLDsa();
        var pubKey = signer.ExportMLDsaPublicKey()!;
        using var verifier = McpMessageSigner.CreateMLDsaVerifier(pubKey);

        var envelope = signer.SignMessage("""{"verify":"cross-party"}""", "sender-a");
        var result = verifier.VerifyMessage(envelope);

        Assert.True(result.IsValid);
        Assert.Equal("sender-a", result.SenderId);
    }

    [RequiresMldsaSupportFact]
    public void MLDsa_Disposable_NoThrowOnDoubleDispose()
    {
        var signer = McpMessageSigner.CreateMLDsa();
        signer.Dispose();
        signer.Dispose(); // should not throw
    }
#endif

    private sealed class ThrowingNonceStore : IMcpNonceStore
    {
        public Task<bool> ContainsAsync(string nonce, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException(@"C:\sensitive\path");
        }

        public Task<bool> AddAsync(string nonce, DateTimeOffset timestamp, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException(@"C:\sensitive\path");
        }

        public Task<int> CleanupAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException(@"C:\sensitive\path");
        }
    }
}
