# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tool-Using Agent - Agent with Safe Tools

Requires: pip install openai
Run with: python agent.py
Or: python agent.py --task "Calculate 15% tip on $84.50"

Note: This example requires the safe toolkit module and an OpenAI API key.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any, List

from agent_os import KernelSpace
from atr import get_registry
from atr.tools.safe import create_safe_toolkit


# Initialize kernel
kernel = KernelSpace(policy="strict")

# Initialize tool registry with safe tools
registry = get_registry()
toolkit = create_safe_toolkit("standard", config={
    "allowed_domains": [
        "api.github.com",
        "httpbin.org",
        "api.weather.gov"
    ],
    "sandbox_paths": ["./data"],
    "allowed_extensions": [".txt", ".json", ".md", ".csv"],
    "rate_limit": 30
})
toolkit["register_all"](registry)


# Tool descriptions for the LLM
TOOL_DESCRIPTIONS = """
Available tools:
1. calculate(expression) - Evaluate math: calculate("2 + 2 * 3") → 8
2. http_get(url) - Fetch URL data: http_get("https://api.github.com/users/octocat")
3. read_file(path) - Read file: read_file("data/config.json")
4. parse_json(data) - Parse JSON string: parse_json('{"key": "value"}')
5. datetime_now() - Get current time with timezone
6. text_analyze(text) - Analyze text (word count, sentences, etc.)

To use a tool, respond with:
TOOL: tool_name
ARGS: {"arg1": "value1", "arg2": "value2"}

After receiving tool output, provide your final response.
"""


@kernel.register
async def tool_agent(task: str) -> str:
    """
    An agent that uses tools to accomplish tasks.
    
    Args:
        task: The task to accomplish
    
    Returns:
        The result of the task
    """
    try:
        from openai import OpenAI
        client = OpenAI()
    except ImportError:
        return "Error: openai package required. Install with: pip install openai"
    
    messages = [
        {
            "role": "system",
            "content": f"""You are a helpful assistant with access to tools.
            
{TOOL_DESCRIPTIONS}

Think step by step. Use tools when needed. Be concise."""
        },
        {
            "role": "user",
            "content": task
        }
    ]
    
    # Conversation loop (max 5 tool calls)
    for _ in range(5):
        response = client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4"),
            messages=messages,
            max_tokens=500,
            temperature=0
        )
        
        assistant_message = response.choices[0].message.content
        
        # Check if agent wants to use a tool
        if "TOOL:" in assistant_message:
            tool_result = await execute_tool_call(assistant_message)
            
            messages.append({"role": "assistant", "content": assistant_message})
            messages.append({"role": "user", "content": f"Tool result:\n{tool_result}"})
        else:
            # No more tool calls, return response
            return assistant_message
    
    return "Max tool calls reached. " + assistant_message


async def execute_tool_call(message: str) -> str:
    """Parse and execute a tool call from the assistant's message."""
    try:
        # Parse tool name
        tool_line = [l for l in message.split('\n') if l.startswith('TOOL:')][0]
        tool_name = tool_line.replace('TOOL:', '').strip()
        
        # Parse arguments
        args_line = [l for l in message.split('\n') if l.startswith('ARGS:')][0]
        args_json = args_line.replace('ARGS:', '').strip()
        args = json.loads(args_json) if args_json else {}
        
        # Execute tool
        tool = registry.get_tool(tool_name)
        if not tool:
            return f"Error: Unknown tool '{tool_name}'"
        
        result = tool(**args)
        
        # Handle async tools
        if asyncio.iscoroutine(result):
            result = await result
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return f"Error executing tool: {e}"


async def main():
    """Main entry point."""
    print("🔧 Tool-Using Agent")
    print("=" * 40)
    
    # Get task from command line or prompt
    if len(sys.argv) > 2 and sys.argv[1] == "--task":
        task = " ".join(sys.argv[2:])
    else:
        task = input("Enter task (or press Enter for demo): ").strip()
        if not task:
            task = "What is 15% tip on a $84.50 bill?"
    
    print(f"\n📋 Task: {task}")
    print("-" * 40)
    
    # Execute through kernel
    try:
        result = await kernel.execute(tool_agent, task)
        print(f"\n✅ Result:\n{result}")
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
