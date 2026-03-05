# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chat Agent - Interactive Conversational Agent with Memory

Run with: python chat.py
"""

import asyncio
import os
from typing import List, Dict, Optional

from agent_os import KernelSpace, AgentSignal
from memory import EpisodicMemory


# Initialize kernel
kernel = KernelSpace(
    policy_file="policies.yaml" if os.path.exists("policies.yaml") else "strict"
)

# Initialize memory
memory = EpisodicMemory(
    max_turns=50,
    summarize_after=20
)


@kernel.register
async def chat_agent(user_message: str, conversation_id: str = "default") -> str:
    """
    Process a chat message and generate a response.
    
    Args:
        user_message: The user's input message
        conversation_id: Unique ID for this conversation
    
    Returns:
        Agent's response
    """
    # Get conversation history
    history = memory.get_history(conversation_id)
    
    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": """You are a helpful, friendly assistant. 
            Be concise but thorough. If you don't know something, say so.
            Never provide harmful, illegal, or unethical information."""
        }
    ]
    
    # Add history
    for turn in history:
        messages.append({"role": "user", "content": turn["user"]})
        messages.append({"role": "assistant", "content": turn["assistant"]})
    
    # Add current message
    messages.append({"role": "user", "content": user_message})
    
    # Call LLM
    try:
        from openai import OpenAI
        client = OpenAI()
        
        response = client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4"),
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )
        
        assistant_message = response.choices[0].message.content
        
    except ImportError:
        # Fallback for demo without OpenAI
        assistant_message = f"Echo: {user_message} (Install openai package for real responses)"
    
    # Store in memory
    memory.add_turn(conversation_id, user_message, assistant_message)
    
    return assistant_message


async def interactive_chat():
    """Run interactive chat loop."""
    print("🤖 Chat Agent")
    print("=" * 40)
    print("Type 'quit' to exit, 'clear' to reset memory")
    print("=" * 40)
    print()
    
    conversation_id = "interactive"
    
    while True:
        try:
            # Get user input
            user_input = input("You: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() == "quit":
                print("\nGoodbye! 👋")
                break
            
            if user_input.lower() == "clear":
                memory.clear(conversation_id)
                print("Memory cleared.\n")
                continue
            
            # Process through kernel
            try:
                response = await kernel.execute(
                    chat_agent,
                    user_input,
                    conversation_id
                )
                print(f"\nAgent: {response}\n")
                
            except Exception as e:
                if "SIGSTOP" in str(e):
                    print("\n⚠️  Response flagged for review. Skipping.\n")
                elif "SIGKILL" in str(e):
                    print("\n🛑 Response blocked by policy.\n")
                else:
                    print(f"\n❌ Error: {e}\n")
        
        except KeyboardInterrupt:
            print("\n\nGoodbye! 👋")
            break


async def main():
    """Main entry point."""
    await interactive_chat()


if __name__ == "__main__":
    asyncio.run(main())
