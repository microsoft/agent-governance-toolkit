package agentmesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// AgentIdentity holds an agent's DID and Ed25519 key pair.
type AgentIdentity struct {
	DID          string              `json:"did"`
	PublicKey    ed25519.PublicKey    `json:"public_key"`
	Capabilities []string            `json:"capabilities,omitempty"`
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

// ToJSON serialises the public portion of the identity.
func (a *AgentIdentity) ToJSON() ([]byte, error) {
	return json.Marshal(identityJSON{
		DID:          a.DID,
		PublicKey:    []byte(a.PublicKey),
		Capabilities: a.Capabilities,
	})
}

// FromJSON deserialises an identity from JSON (public fields only).
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
