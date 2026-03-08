#!/bin/bash
# Agent OS Quickstart Script
# Run with: curl -sSL https://get.agent-os.dev | bash

set -e

echo "🛡️  Agent OS Quickstart"
echo "========================"
echo ""

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "   Install Python 3.10+ from https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✅ Found Python $PYTHON_VERSION"

# Install Agent OS
echo ""
echo "📦 Installing Agent OS..."
pip3 install --no-cache-dir --quiet "agent-os>=0.1.0,<2"

echo "✅ Agent OS installed"

# Create demo project
DEMO_DIR="agent-os-demo"
echo ""
echo "📁 Creating demo project in ./$DEMO_DIR"

mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

# Create a simple agent
cat > agent.py << 'EOF'
"""Agent OS Demo - Your First Governed Agent"""

import asyncio
from agent_os import KernelSpace

kernel = KernelSpace(policy="strict")

@kernel.register
async def my_agent(task: str) -> str:
    result = f"Processed: {task.upper()}"
    return result

async def main():
    print("🛡️  Agent OS Demo")
    print("=" * 40)
    result = await kernel.execute(my_agent, "Hello, Agent OS!")
    print(f"✅ Result: {result}")
    print("\n🎉 Your agent ran safely under kernel governance!")

if __name__ == "__main__":
    asyncio.run(main())
EOF

echo "✅ Created agent.py"

# Run the demo
echo ""
echo "🚀 Running your first governed agent..."
echo ""

python3 agent.py

echo ""
echo "🎉 Quickstart Complete!"
echo "   Project: $(pwd)"
echo "   Docs: https://agent-os.dev/docs"
