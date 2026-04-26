# CrewAI Integration with AgentMesh

Govern your CrewAI multi-agent crews with AgentMesh identity, delegation, and trust scoring.

## Why Integrate AgentMesh with CrewAI?

CrewAI provides collaborative multi-agent workflows, but AgentMesh adds:
- **Cryptographic identity** for each crew member
- **Scope chains** with narrowing capabilities
- **Cross-agent trust handshakes**
- **Collaborative trust scoring**

## Quick Start

### Installation

```bash
pip install agentmesh-platform crewai crewai-tools
```

### Basic Integration

```python
from crewai import Agent, Task, Crew
from agentmesh import AgentIdentity, ScopeChain, PolicyEngine

# Create supervisor identity
supervisor_identity = AgentIdentity.create(
    name="crew-supervisor",
    sponsor="team-lead@company.com",
    capabilities=["research", "writing", "review"]
)

# Create scope chain
scope_chain = ScopeChain(root=supervisor_identity)

# Delegate to crew members
researcher_identity = scope_chain.delegate(
    name="researcher-agent",
    capabilities=["research"]  # Narrowed from supervisor
)

writer_identity = scope_chain.delegate(
    name="writer-agent",
    capabilities=["writing"]  # Narrowed from supervisor
)

reviewer_identity = scope_chain.delegate(
    name="reviewer-agent",
    capabilities=["review"]  # Narrowed from supervisor
)

# Create CrewAI agents with AgentMesh identities
researcher = Agent(
    role="Researcher",
    goal="Research the topic thoroughly",
    backstory="Expert researcher with 10 years experience",
    agentmesh_identity=researcher_identity  # Attach identity
)

writer = Agent(
    role="Writer",
    goal="Write engaging content",
    backstory="Professional content writer",
    agentmesh_identity=writer_identity
)

reviewer = Agent(
    role="Reviewer",
    goal="Review and improve content",
    backstory="Senior editor with high standards",
    agentmesh_identity=reviewer_identity
)

# Define tasks
research_task = Task(
    description="Research the topic: AgentMesh governance for AI agents",
    agent=researcher
)

writing_task = Task(
    description="Write a blog post based on the research",
    agent=writer
)

review_task = Task(
    description="Review and improve the blog post",
    agent=reviewer
)

# Create governed crew
crew = Crew(
    agents=[researcher, writer, reviewer],
    tasks=[research_task, writing_task, review_task],
    verbose=True
)

# Run with governance
result = crew.kickoff()

print(f"Result: {result}")
print(f"Supervisor DID: {supervisor_identity.did}")
print(f"Crew members: {len(scope_chain.links)}")
```

## Advanced Features

### 1. Trust Handshakes Between Crew Members

```python
from agentmesh import TrustHandshake

# Before writer accepts work from researcher
async def governed_task_handoff(from_agent, to_agent, task):
    handshake = TrustHandshake()
    
    # Verify peer
    result = await handshake.verify(
        peer_did=from_agent.agentmesh_identity.did,
        required_score=700
    )
    
    if not result.verified:
        raise SecurityError(f"Untrusted peer: {result.reason}")
    
    # Accept task
    return to_agent.execute(task)
```

### 2. Collaborative Trust Scoring

```python
from agentmesh import RewardEngine

reward_engine = RewardEngine()

# Update scores based on collaboration quality
def update_crew_scores(crew):
    for agent in crew.agents:
        identity = agent.agentmesh_identity
        
        # Score based on:
        # - Task completion quality
        # - Collaboration with other agents
        # - Policy compliance
        
        score = reward_engine.update_score(
            agent_id=identity.did,
            dimensions={
                "task_quality": 0.9,
                "collaboration": 0.85,
                "policy_compliance": 1.0
            }
        )
        
        print(f"{agent.role}: {score.total}/1000")
```

### 3. Policy Enforcement on Crew Tasks

```python
policy_engine = PolicyEngine.from_file("policies/crew.yaml")

# Wrap task execution with policy checks
def governed_task_execution(task, agent):
    # Check policy before execution
    result = policy_engine.check(
        action="execute_task",
        agent=agent.agentmesh_identity.did,
        task=task.description
    )
    
    if not result.allowed:
        raise PermissionError(f"Policy violation: {result.reason}")
    
    # Execute task
    output = agent.execute_task(task)
    
    # Audit
    audit_log.log("task_completed", agent=agent.role, task=task.description)
    
    return output
```

## Real-World Example: Content Creation Crew

```python
from crewai import Agent, Task, Crew, Process
from agentmesh import AgentIdentity, ScopeChain, PolicyEngine, AuditLog

# Initialize AgentMesh
supervisor = AgentIdentity.create(
    name="content-crew-supervisor",
    sponsor="marketing@company.com",
    capabilities=["research", "writing", "seo", "social_media"]
)

scope_chain = ScopeChain(root=supervisor)
policy_engine = PolicyEngine.from_file("policies/content-crew.yaml")
audit_log = AuditLog(agent_id=supervisor.did)

# Create specialized agents
seo_specialist = Agent(
    role="SEO Specialist",
    goal="Optimize content for search engines",
    agentmesh_identity=scope_chain.delegate(
        name="seo-specialist",
        capabilities=["research", "seo"]
    )
)

content_writer = Agent(
    role="Content Writer",
    goal="Write engaging, SEO-optimized content",
    agentmesh_identity=scope_chain.delegate(
        name="content-writer",
        capabilities=["writing"]
    )
)

social_media_manager = Agent(
    role="Social Media Manager",
    goal="Create social media posts",
    agentmesh_identity=scope_chain.delegate(
        name="social-media-manager",
        capabilities=["social_media", "writing"]
    )
)

# Define workflow
tasks = [
    Task(
        description="Research keywords for 'AI agent governance'",
        agent=seo_specialist
    ),
    Task(
        description="Write a 1000-word blog post about AI agent governance",
        agent=content_writer
    ),
    Task(
        description="Create 5 social media posts to promote the blog",
        agent=social_media_manager
    ),
]

# Create governed crew
crew = Crew(
    agents=[seo_specialist, content_writer, social_media_manager],
    tasks=tasks,
    process=Process.sequential,  # Sequential execution
    verbose=True
)

# Execute with governance
result = crew.kickoff()

# Generate compliance report
print("\n=== Governance Report ===")
print(f"Supervisor: {supervisor.did}")
print(f"Crew size: {len(crew.agents)}")
print(f"Tasks completed: {len(tasks)}")
print(f"Audit entries: {len(audit_log.entries)}")
```

## Policy Examples

### Prevent Brand Risk

```yaml
policies:
  - name: "brand-safety"
    rules:
      - condition: "output contains 'controversial_topic'"
        action: "require_approval"
        approvers: ["legal@company.com"]
```

### Rate Limit External API Calls

```yaml
policies:
  - name: "api-rate-limit"
    rules:
      - condition: "action == 'api_call'"
        limit: "1000/day"
        action: "block"
```

## Best Practices

1. **Use scope chains** for crew hierarchies
2. **Narrow capabilities** for specialized agents
3. **Enable trust handshakes** for collaboration
4. **Monitor trust scores** across the crew
5. **Audit all task completions** for compliance

## Learn More

- [CrewAI Documentation](https://docs.crewai.com/)
- [AgentMesh Delegation](../../docs/delegation.md)
- [Multi-Agent Governance](../../docs/multi-agent.md)

---

**Production Ready:** Yes, with monitoring and proper secret management.
