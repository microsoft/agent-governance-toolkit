package agentmesh

import (
	"context"
	"fmt"
)

// AgentMeshClient is the unified governance client.
type AgentMeshClient struct {
	Identity  *AgentIdentity
	Trust     *TrustManager
	Policy    *PolicyEngine
	Audit     *AuditLogger
	Approvals *ApprovalCoordinator
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

	audit := NewAuditLogger()
	if o.approvalCoordinator != nil && o.approvalCoordinator.audit == nil {
		o.approvalCoordinator.audit = audit
	}

	return &AgentMeshClient{
		Identity:  identity,
		Trust:     NewTrustManager(trustCfg),
		Policy:    NewPolicyEngine(rules),
		Audit:     audit,
		Approvals: o.approvalCoordinator,
	}, nil
}

// ExecuteWithGovernance evaluates the action through the governance pipeline.
func (c *AgentMeshClient) ExecuteWithGovernance(action string, params map[string]interface{}) (*GovernanceResult, error) {
	return c.ExecuteWithGovernanceContext(context.Background(), action, params)
}

// ExecuteWithGovernanceContext evaluates the action through the governance pipeline.
func (c *AgentMeshClient) ExecuteWithGovernanceContext(ctx context.Context, action string, params map[string]interface{}) (*GovernanceResult, error) {
	if c.Policy == nil || c.Audit == nil || c.Identity == nil || c.Trust == nil {
		return nil, fmt.Errorf("AgentMeshClient is not fully initialised: ensure NewClient was used")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	decision := c.Policy.Evaluate(action, params)
	var approval *ApprovalResult
	if decision == RequiresApproval && c.Approvals != nil {
		binding := ActionBinding{
			Operation: "agentmesh.execute",
			AgentID:   c.Identity.DID,
			Target: ActionTarget{
				ToolName:          action,
				ToolSchemaVersion: "1.0",
			},
			Parameters: clonePolicyContext(params),
		}
		resolved, err := c.Approvals.RequestApproval(ctx, binding)
		if resolved != nil {
			approval = resolved
		}
		if err != nil {
			decision = Deny
		} else {
			decision = resolved.Decision
		}
	}

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
		Approval:   approval,
	}, nil
}
