# LangChain Integration with AgentMesh

Secure your LangChain agents with AgentMesh governance, identity, and trust scoring.

## Why Integrate AgentMesh with LangChain?

LangChain provides powerful agent orchestration, but lacks:
- **Cryptographic identity** for agents
- **Policy enforcement** on tool usage
- **Audit logging** for compliance
- **Trust scoring** for adaptive governance

AgentMesh fills these gaps.

## Quick Start

### Installation

```bash
pip install agentmesh-platform langchain langchain-openai
```

### Basic Integration

```python
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain_openai import ChatOpenAI
from langchain.tools import Tool
from agentmesh import AgentIdentity, PolicyEngine, AuditLog

# Create AgentMesh identity
identity = AgentIdentity.create(
    name="langchain-agent",
    sponsor="dev@company.com",
    capabilities=["tool:search", "tool:calculator"]
)

# Initialize governance
policy_engine = PolicyEngine.from_file("policies/default.yaml")
audit_log = AuditLog(agent_id=identity.did)

# Wrap LangChain tools with governance
def governed_tool(tool_func):
    """Decorator to add governance to LangChain tools."""
    def wrapper(*args, **kwargs):
        # Policy check
        result = policy_engine.check(
            action="tool_call",
            tool=tool_func.__name__,
            params=kwargs
        )
        
        if not result.allowed:
            audit_log.log("blocked", tool=tool_func.__name__, reason=result.reason)
            raise PermissionError(f"Policy violation: {result.reason}")
        
        # Execute tool
        output = tool_func(*args, **kwargs)
        
        # Audit
        audit_log.log("success", tool=tool_func.__name__, output=output)
        
        return output
    
    return wrapper

# Define tools with governance
@governed_tool
def search(query: str) -> str:
    """Search the web."""
    return f"Search results for: {query}"

@governed_tool
def calculator(expression: str) -> str:
    """Calculate a mathematical expression."""
    # Safe evaluation - DO NOT use eval() in production
    # Use a safe math parser like simpleeval or ast.literal_eval with validation
    try:
        # For demo purposes only - replace with safe parser in production
        # Example with simpleeval: return str(simpleeval.simple_eval(expression))
        import ast
        import operator
        
        # Define safe operations
        safe_ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow,
        }
        
        def safe_eval(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return safe_ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
            else:
                raise ValueError("Unsafe operation")
        
        tree = ast.parse(expression, mode='eval')
        return str(safe_eval(tree.body))
    except Exception as e:
        return f"Error: {str(e)}"

# Create LangChain tools
tools = [
    Tool(
        name="Search",
        func=search,
        description="Search the web for information"
    ),
    Tool(
        name="Calculator",
        func=calculator,
        description="Calculate mathematical expressions"
    ),
]

# Create LangChain agent with governed tools
llm = ChatOpenAI(model="gpt-4")
agent = create_openai_functions_agent(llm, tools)
agent_executor = AgentExecutor(agent=agent, tools=tools)

# Run the agent
result = agent_executor.invoke({
    "input": "What is the square root of 144?"
})

print(f"Result: {result}")
print(f"Agent DID: {identity.did}")
print(f"Audit entries: {len(audit_log.entries)}")
```

## Advanced Features

### 1. Rate Limiting on Tools

```yaml
# policies/langchain.yaml
policies:
  - name: "rate-limit-search"
    rules:
      - condition: "tool == 'Search'"
        limit: "100/hour"
        action: "block"
```

### 2. Trust Score Integration

```python
from agentmesh import RewardEngine

reward_engine = RewardEngine()

# Update trust score after each agent run
score = reward_engine.update_score(
    agent_id=identity.did,
    action="agent_execution",
    success=True
)

# Revoke credentials if trust score drops
if score.total < 500:
    identity.revoke_credentials()
```

### 3. Multi-Agent with Delegation

```python
# Create supervisor agent
supervisor = AgentIdentity.create(
    name="langchain-supervisor",
    sponsor="team@company.com",
    capabilities=["tool:*"]
)

# Delegate to worker agents with narrowed capabilities
worker1 = supervisor.delegate(
    name="langchain-worker-1",
    capabilities=["tool:search"]
)

worker2 = supervisor.delegate(
    name="langchain-worker-2",
    capabilities=["tool:calculator"]
)
```

## Real-World Example: RAG with Governance

```python
from langchain.chains import RetrievalQA
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings

# Create governed RAG agent
identity = AgentIdentity.create(
    name="rag-agent",
    sponsor="knowledge-team@company.com",
    capabilities=["read:docs", "query:vectordb"]
)

# Load vector store with governance
policy_engine = PolicyEngine.from_file("policies/rag.yaml")

def governed_retrieval(query: str):
    # Check policy
    result = policy_engine.check(action="query_vectordb", params={"query": query})
    if not result.allowed:
        raise PermissionError(result.reason)
    
    # Perform retrieval
    embeddings = OpenAIEmbeddings()
    vectorstore = Chroma(embedding_function=embeddings)
    docs = vectorstore.similarity_search(query)
    
    # Audit
    audit_log.log("retrieval", query=query, num_docs=len(docs))
    
    return docs

# Create RAG chain
qa_chain = RetrievalQA.from_chain_type(
    llm=ChatOpenAI(),
    retriever=governed_retrieval
)

# Query with governance
answer = qa_chain.run("What is AgentMesh?")
```

## Policy Examples

### Prevent PII Leakage

```yaml
policies:
  - name: "no-pii-in-output"
    rules:
      - condition: "output contains 'ssn' or output contains 'email'"
        action: "redact"
```

### Require Approval for Sensitive Tools

```yaml
policies:
  - name: "approve-database-queries"
    rules:
      - condition: "tool == 'DatabaseQuery'"
        action: "require_approval"
        approvers: ["security-team@company.com"]
```

## Best Practices

1. **Always wrap tools** with governance decorators
2. **Use narrow capabilities** for worker agents
3. **Enable audit logging** for compliance
4. **Monitor trust scores** and set alerts
5. **Test policies** in shadow mode first

## Troubleshooting

**Issue:** LangChain agent keeps getting blocked

**Solution:** Check your policy rules and ensure they match your use case

---

**Issue:** Trust score keeps dropping

**Solution:** Review audit logs for policy violations or tool failures

## Learn More

- [LangChain Documentation](https://python.langchain.com/)
- [AgentMesh Policy Engine](../../docs/policy-engine.md)
- [Trust Scoring Guide](../../docs/trust-scoring.md)

---

**Production Ready:** Yes, with proper secret management and monitoring.
