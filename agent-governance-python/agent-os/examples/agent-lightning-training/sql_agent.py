# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
SQL Agent Training with Agent-Lightning
========================================

Demonstrates training a SQL agent with RL while enforcing
safety policies through Agent OS.

The agent learns to:
1. Generate accurate SQL queries
2. NEVER violate safety policies (no DROP, DELETE, etc.)
3. Stay within cost limits

Run:
    pip install agent-os-kernel agentlightning
    python sql_agent.py
"""

import asyncio
import logging
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# MOCK COMPONENTS (Replace with real implementations)
# ============================================================

class MockKernelSpace:
    """Mock kernel for demonstration."""
    
    def __init__(self, policy=None):
        self.policy = policy or []
        self.violations = []
        self._violation_callbacks = []
    
    def on_policy_violation(self, callback):
        self._violation_callbacks.append(callback)
    
    def execute(self, agent, task):
        """Execute with policy checking."""
        # Simulate policy check
        if "DROP" in str(task).upper() or "DELETE" in str(task).upper():
            for cb in self._violation_callbacks:
                cb(
                    policy_name="SQLPolicy",
                    description="Dangerous SQL operation blocked",
                    severity="critical",
                    blocked=True,
                )
            return None
        
        return {"result": f"Executed: {task}", "accuracy": 0.85}
    
    def reset(self):
        self.violations = []


class MockSQLPolicy:
    """Mock SQL policy."""
    
    def __init__(self, allow=None, deny=None):
        self.allow = allow or ["SELECT"]
        self.deny = deny or ["DROP", "DELETE"]
        self.name = "SQLPolicy"


class MockCostControlPolicy:
    """Mock cost control policy."""
    
    def __init__(self, max_cost_usd=100):
        self.max_cost_usd = max_cost_usd
        self.name = "CostControlPolicy"


# ============================================================
# TRAINING EXAMPLE
# ============================================================

async def train_sql_agent():
    """Train a SQL agent with governance."""
    
    # Import Agent OS integration
    from agent_lightning_gov import (
        GovernedRunner,
        PolicyReward,
        GovernedEnvironment,
    )
    
    print("=" * 60)
    print("SQL Agent Training with Agent-Lightning + Agent OS")
    print("=" * 60)
    
    # 1. Create kernel with policies
    kernel = MockKernelSpace(policy=[
        MockSQLPolicy(
            allow=["SELECT", "INSERT", "UPDATE"],
            deny=["DROP", "DELETE", "TRUNCATE"],
        ),
        MockCostControlPolicy(max_cost_usd=100),
    ])
    
    print("\n✓ Kernel initialized with policies:")
    print("  - SQLPolicy: Allow SELECT/INSERT/UPDATE, Deny DROP/DELETE")
    print("  - CostControlPolicy: Max $100 per query")
    
    # 2. Create governed runner
    runner = GovernedRunner(
        kernel,
        fail_on_violation=False,
        log_violations=True,
    )
    
    # Mock agent initialization
    class MockAgent:
        name = "SQLAgent"
        def __call__(self, task):
            return {"result": task, "accuracy": 0.9}
    
    runner.init(MockAgent())
    runner.init_worker(0, None)
    
    print("\n✓ GovernedRunner initialized")
    
    # 3. Create policy-aware reward function
    def accuracy_reward(rollout):
        if rollout.success and rollout.task_output:
            return rollout.task_output.get("accuracy", 0.0)
        return 0.0
    
    reward_fn = PolicyReward(kernel, base_reward_fn=accuracy_reward)
    print("✓ PolicyReward function created")
    
    # 4. Simulate training episodes
    print("\n" + "=" * 60)
    print("Training Episodes")
    print("=" * 60)
    
    test_queries = [
        "SELECT * FROM users WHERE id = 1",
        "INSERT INTO logs (msg) VALUES ('hello')",
        "DROP TABLE users",  # Should be blocked!
        "UPDATE users SET name = 'John' WHERE id = 1",
        "DELETE FROM users WHERE id = 1",  # Should be blocked!
        "SELECT COUNT(*) FROM orders",
    ]
    
    total_reward = 0.0
    violations_count = 0
    
    for i, query in enumerate(test_queries):
        print(f"\nEpisode {i+1}: {query[:50]}...")
        
        # Execute through governed runner
        rollout = await runner.step(query)
        
        # Calculate reward
        reward = reward_fn(rollout, emit=False)
        total_reward += reward
        violations_count += len(rollout.violations)
        
        # Report
        status = "✅ SUCCESS" if rollout.success else "❌ BLOCKED"
        print(f"  Status: {status}")
        print(f"  Violations: {len(rollout.violations)}")
        print(f"  Reward: {reward:.2f}")
        
        if rollout.violations:
            for v in rollout.violations:
                print(f"  ⚠️  {v.policy_name}: {v.description}")
    
    # 5. Report final statistics
    print("\n" + "=" * 60)
    print("Training Summary")
    print("=" * 60)
    
    stats = runner.get_stats()
    reward_stats = reward_fn.get_stats()
    
    print(f"\nRunner Statistics:")
    print(f"  Total rollouts: {stats['total_rollouts']}")
    print(f"  Total violations: {stats['total_violations']}")
    print(f"  Violation rate: {stats['violation_rate']:.1%}")
    
    print(f"\nReward Statistics:")
    print(f"  Total reward: {total_reward:.2f}")
    print(f"  Avg penalty: {reward_stats['avg_penalty']:.2f}")
    print(f"  Clean rate: {reward_stats['clean_rate']:.1%}")
    
    print("\n" + "=" * 60)
    print("Key Insight: Agent learns that DROP/DELETE → negative reward")
    print("After training, agent will avoid dangerous SQL operations!")
    print("=" * 60)
    
    # Cleanup
    runner.teardown()


async def demo_environment():
    """Demonstrate the GovernedEnvironment."""
    
    from agent_lightning_gov import (
        GovernedEnvironment,
        EnvironmentConfig,
    )
    
    print("\n" + "=" * 60)
    print("GovernedEnvironment Demo")
    print("=" * 60)
    
    kernel = MockKernelSpace()
    
    config = EnvironmentConfig(
        max_steps=10,
        violation_penalty=-10.0,
        terminate_on_critical=True,
    )
    
    env = GovernedEnvironment(kernel, config=config)
    
    # Run episode
    state, info = env.reset()
    print(f"\nEpisode started. Policies: {info.get('kernel_policies', [])}")
    
    actions = ["SELECT * FROM users", "UPDATE users SET x=1", "DROP TABLE users"]
    
    for action in actions:
        if env.terminated:
            break
        
        state, reward, terminated, truncated, info = env.step(action)
        print(f"\nAction: {action[:30]}...")
        print(f"  Reward: {reward:.2f}")
        print(f"  Terminated: {terminated}")
        print(f"  Violations: {len(info.get('violations', []))}")
    
    print(f"\nEnvironment Metrics:")
    metrics = env.get_metrics()
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.2f}")
        else:
            print(f"  {k}: {v}")
    
    env.close()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Agent OS + Agent-Lightning Integration Demo")
    print("=" * 60 + "\n")
    
    # Run training demo
    asyncio.run(train_sql_agent())
    
    # Run environment demo
    asyncio.run(demo_environment())
    
    print("\n✅ Demo complete!")
