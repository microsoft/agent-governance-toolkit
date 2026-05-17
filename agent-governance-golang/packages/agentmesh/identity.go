package agentmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// AgentIdentity holds an agent's DID and Ed25519 key pair.
type AgentIdentity struct {
	DID          string            `json:"did"`
	PublicKey    ed25519.PublicKey `json:"public_key"`
	Capabilities []string          `json:"capabilities,omitempty"`
	privateKey   ed25519.PrivateKey
}

// GenerateIdentity creates a new Ed25519-based identity for the given agent.
func GenerateIdentity(agentID string, capabilities []string) (*AgentIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key pair: %w", err)
	}
	return &AgentIdentity{
		DID:          fmt.Sprintf("did:agentmesh:%s", agentID),
		PublicKey:    pub,
		Capabilities: capabilities,
		privateKey:   priv,
	}, nil
}

// Sign signs data with the agent's private key.
func (a *AgentIdentity) Sign(data []byte) ([]byte, error) {
	if a.privateKey == nil {
		return nil, fmt.Errorf("no private key available")
	}
	return ed25519.Sign(a.privateKey, data), nil
}

// Verify checks a signature against data using the agent's public key.
func (a *AgentIdentity) Verify(data, signature []byte) bool {
	return ed25519.Verify(a.PublicKey, data, signature)
}

// identityJSON is used for JSON marshalling (excludes private key).
type identityJSON struct {
	DID          string   `json:"did"`
	PublicKey    []byte   `json:"public_key"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ToJSON serialises the public portion of the identity (DID, public key,
// capabilities). The private key is deliberately excluded so the output is
// safe to share with peers, store in registries, or transmit over untrusted
// channels.
//
// There is intentionally no symmetric ToPrivateJSON: private keys live only
// in-process and should be persisted via a key management system, not by
// round-tripping through this package. An identity rehydrated via FromJSON
// can Verify peer signatures but cannot Sign — calling Sign on such an
// identity returns an error.
func (a *AgentIdentity) ToJSON() ([]byte, error) {
	return json.Marshal(identityJSON{
		DID:          a.DID,
		PublicKey:    []byte(a.PublicKey),
		Capabilities: a.Capabilities,
	})
}

// FromJSON deserialises an identity from the public-only JSON format produced
// by ToJSON. The resulting identity has no private key, so it can Verify
// signatures from the original agent but cannot Sign new data. To obtain a
// signing-capable identity, call GenerateIdentity or load the private key
// from a key management system separately.
func FromJSON(data []byte) (*AgentIdentity, error) {
	var j identityJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("unmarshalling identity: %w", err)
	}
	return &AgentIdentity{
		DID:          j.DID,
		PublicKey:    ed25519.PublicKey(j.PublicKey),
		Capabilities: j.Capabilities,
	}, nil
}
