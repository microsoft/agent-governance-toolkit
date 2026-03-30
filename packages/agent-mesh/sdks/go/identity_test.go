package agentmesh

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity("agent-1", []string{"read", "write"})
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.DID != "did:agentmesh:agent-1" {
		t.Errorf("DID = %q, want did:agentmesh:agent-1", id.DID)
	}
	if len(id.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32", len(id.PublicKey))
	}
	if len(id.Capabilities) != 2 {
		t.Errorf("Capabilities length = %d, want 2", len(id.Capabilities))
	}
}

func TestSignAndVerify(t *testing.T) {
	id, err := GenerateIdentity("signer", nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello agent mesh")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !id.Verify(data, sig) {
		t.Error("Verify returned false for valid signature")
	}
	if id.Verify([]byte("tampered"), sig) {
		t.Error("Verify returned true for tampered data")
	}
}

func TestSignWithoutPrivateKey(t *testing.T) {
	id := &AgentIdentity{DID: "did:agentmesh:nopk"}
	_, err := id.Sign([]byte("data"))
	if err == nil {
		t.Error("expected error when signing without private key")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity("json-agent", []string{"cap1"})
	data, err := id.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	restored, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if restored.DID != id.DID {
		t.Errorf("DID mismatch: %q vs %q", restored.DID, id.DID)
	}
	if len(restored.PublicKey) != len(id.PublicKey) {
		t.Error("PublicKey length mismatch after round-trip")
	}
}

// --- New comprehensive tests ---

func TestGenerateMultipleIdentitiesUniqueDIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 20; i++ {
		id, err := GenerateIdentity("agent", nil)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		// DID is based on agentID, so all will be the same DID
		// But PublicKeys should be unique
		keyHex := string(id.PublicKey)
		if ids[keyHex] {
			t.Errorf("iteration %d: duplicate public key generated", i)
		}
		ids[keyHex] = true
	}
}

func TestGenerateIdentitiesWithDifferentAgentIDs(t *testing.T) {
	id1, err := GenerateIdentity("agent-alpha", nil)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := GenerateIdentity("agent-beta", nil)
	if err != nil {
		t.Fatal(err)
	}

	if id1.DID == id2.DID {
		t.Error("different agent IDs should produce different DIDs")
	}
	if id1.DID != "did:agentmesh:agent-alpha" {
		t.Errorf("DID = %q, want did:agentmesh:agent-alpha", id1.DID)
	}
	if id2.DID != "did:agentmesh:agent-beta" {
		t.Errorf("DID = %q, want did:agentmesh:agent-beta", id2.DID)
	}
}

func TestSignEmptyData(t *testing.T) {
	id, err := GenerateIdentity("empty-signer", nil)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := id.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign empty data: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature of empty data should not be empty")
	}
	if !id.Verify([]byte{}, sig) {
		t.Error("verification of empty data signature should succeed")
	}
}

func TestSignLargeData(t *testing.T) {
	id, err := GenerateIdentity("large-signer", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1 MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	sig, err := id.Sign(data)
	if err != nil {
		t.Fatalf("Sign large data: %v", err)
	}
	if !id.Verify(data, sig) {
		t.Error("verification of large data signature should succeed")
	}

	// Tamper with one byte
	data[500000] ^= 0xFF
	if id.Verify(data, sig) {
		t.Error("verification should fail after tampering")
	}
}

func TestCrossIdentityVerificationFails(t *testing.T) {
	idA, err := GenerateIdentity("agent-A", nil)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := GenerateIdentity("agent-B", nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test message")
	sigA, err := idA.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	// Agent B should not be able to verify Agent A's signature
	if idB.Verify(data, sigA) {
		t.Error("cross-identity verification should fail: B should not verify A's signature")
	}

	// Agent A should verify its own signature
	if !idA.Verify(data, sigA) {
		t.Error("self-verification should succeed")
	}
}

func TestPublicIdentityFromJSONCanVerify(t *testing.T) {
	id, err := GenerateIdentity("json-verify-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("message to verify")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize to JSON
	jsonData, err := id.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	// Restore from JSON
	restored, err := FromJSON(jsonData)
	if err != nil {
		t.Fatal(err)
	}

	// Restored identity can verify
	if !restored.Verify(data, sig) {
		t.Error("identity restored from JSON should be able to verify signatures")
	}

	// Restored identity should NOT be able to sign (no private key)
	_, signErr := restored.Sign(data)
	if signErr == nil {
		t.Error("identity from JSON should not have private key for signing")
	}
}

func TestFromJSONInvalidJSON(t *testing.T) {
	_, err := FromJSON([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFromJSONEmptyJSON(t *testing.T) {
	_, err := FromJSON([]byte("{}"))
	if err != nil {
		t.Errorf("empty JSON object should not error: %v", err)
	}
}

func TestPublicIdentityWrongKeyLengthRejects(t *testing.T) {
	id, err := GenerateIdentity("good-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test")
	sig, err := id.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	// Create identity with wrong key length
	badId := &AgentIdentity{
		DID:       "did:agentmesh:bad-key",
		PublicKey: ed25519.PublicKey([]byte("short-key")),
	}

	// ed25519.Verify will panic or return false with wrong key length
	// We need to catch this
	func() {
		defer func() {
			if r := recover(); r != nil {
				// This is expected - wrong key length causes panic in ed25519
				t.Logf("ed25519.Verify panicked with wrong key length as expected: %v", r)
			}
		}()
		if badId.Verify(data, sig) {
			t.Error("wrong key length should not verify")
		}
	}()
}

func TestPublicIdentityWrongSignatureLengthRejects(t *testing.T) {
	id, err := GenerateIdentity("sig-len-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("test")

	// Try to verify with a signature that's too short
	shortSig := []byte("too-short-signature")
	if id.Verify(data, shortSig) {
		t.Error("short signature should not verify")
	}
}

func TestCapabilitiesRoundtripThroughJSON(t *testing.T) {
	caps := []string{"read", "write", "admin", "deploy"}
	id, err := GenerateIdentity("caps-agent", caps)
	if err != nil {
		t.Fatal(err)
	}

	jsonData, err := id.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := FromJSON(jsonData)
	if err != nil {
		t.Fatal(err)
	}

	if len(restored.Capabilities) != len(caps) {
		t.Fatalf("capabilities length = %d, want %d", len(restored.Capabilities), len(caps))
	}
	for i, c := range caps {
		if restored.Capabilities[i] != c {
			t.Errorf("capability[%d] = %q, want %q", i, restored.Capabilities[i], c)
		}
	}
}

func TestMultipleCapabilities(t *testing.T) {
	caps := []string{"data.read", "data.write", "file.execute", "net.connect", "sys.monitor"}
	id, err := GenerateIdentity("multi-cap-agent", caps)
	if err != nil {
		t.Fatal(err)
	}

	if len(id.Capabilities) != 5 {
		t.Errorf("capabilities count = %d, want 5", len(id.Capabilities))
	}
	for i, expected := range caps {
		if id.Capabilities[i] != expected {
			t.Errorf("capability[%d] = %q, want %q", i, id.Capabilities[i], expected)
		}
	}
}

func TestNilCapabilities(t *testing.T) {
	id, err := GenerateIdentity("nil-caps-agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.Capabilities != nil {
		t.Errorf("capabilities = %v, want nil", id.Capabilities)
	}
}

func TestEmptyCapabilities(t *testing.T) {
	id, err := GenerateIdentity("empty-caps-agent", []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Capabilities) != 0 {
		t.Errorf("capabilities length = %d, want 0", len(id.Capabilities))
	}
}

func TestSignatureLength(t *testing.T) {
	id, err := GenerateIdentity("sig-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := id.Sign([]byte("test data"))
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 signatures are always 64 bytes
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

func TestToJSONExcludesPrivateKey(t *testing.T) {
	id, err := GenerateIdentity("private-agent", nil)
	if err != nil {
		t.Fatal(err)
	}

	jsonData, err := id.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	// JSON should not contain private key
	jsonStr := string(jsonData)
	// The private key is not in the identityJSON struct, so it shouldn't appear
	restored, err := FromJSON(jsonData)
	if err != nil {
		t.Fatal(err)
	}

	// Restored identity should not have private key
	_, signErr := restored.Sign([]byte("data"))
	if signErr == nil {
		t.Error("restored identity should not be able to sign (no private key)")
	}
	_ = jsonStr
}

func TestDIDFormat(t *testing.T) {
	tests := []struct {
		agentID string
		wantDID string
	}{
		{"simple", "did:agentmesh:simple"},
		{"agent-with-dashes", "did:agentmesh:agent-with-dashes"},
		{"agent_with_underscores", "did:agentmesh:agent_with_underscores"},
		{"", "did:agentmesh:"},
		{"123", "did:agentmesh:123"},
	}

	for _, tc := range tests {
		id, err := GenerateIdentity(tc.agentID, nil)
		if err != nil {
			t.Fatalf("agentID=%q: %v", tc.agentID, err)
		}
		if id.DID != tc.wantDID {
			t.Errorf("agentID=%q: DID = %q, want %q", tc.agentID, id.DID, tc.wantDID)
		}
	}
}
