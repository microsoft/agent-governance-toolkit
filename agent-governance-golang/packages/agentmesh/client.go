package agentmesh

import "fmt"

// AgentMeshClient is the unified governance client.
type AgentMeshClient struct {
	Identity *AgentIdentity
	Trust    *TrustManager
	Policy   *PolicyEngine
	Audit    *AuditLogger
}

// NewClient creates a fully initialised AgentMeshClient.
func NewClient(agentID string, opts ...Option) (*AgentMeshClient, error) {
	o := &clientOptions{}
	for _, fn := range opts {
		fn(o)
	}

	identity, err := GenerateIdentity(agentID, o.capabilities)
	if err != nil {
		return nil, fmt.Errorf("creating identity: %w", err)
	}

	trustCfg := DefaultTrustConfig()
	if o.trustConfig != nil {
		trustCfg = *o.trustConfig
	}

	var rules []PolicyRule
	if o.policyRules != nil {
		rules = o.policyRules
	}

	return &AgentMeshClient{
		Identity: identity,
		Trust:    NewTrustManager(trustCfg),
		Policy:   NewPolicyEngine(rules),
		Audit:    NewAuditLogger(),
	}, nil
}

// ExecuteWithGovernance evaluates the action through the governance pipeline.
func (c *AgentMeshClient) ExecuteWithGovernance(action string, params map[string]interface{}) (*GovernanceResult, error) {
	decision := c.Policy.Evaluate(action, params)
	entry := c.Audit.Log(c.Identity.DID, action, decision)
	score := c.Trust.GetTrustScore(c.Identity.DID)

	if decision == Allow {
		c.Trust.RecordSuccess(c.Identity.DID, 0.05)
	} else if decision == Deny {
		c.Trust.RecordFailure(c.Identity.DID, 0.1)
	}

	return &GovernanceResult{
		Decision:   decision,
		TrustScore: score,
		AuditEntry: entry,
		Allowed:    decision == Allow,
	}, nil
}
