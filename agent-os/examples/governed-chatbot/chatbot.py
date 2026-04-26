# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governed Chatbot with Memory — Example for Agent OS

A conversational chatbot that:
- Enforces content policies (no PII, no harmful content)
- Rate-limits user requests
- Maintains conversation memory via the stateless kernel
- Logs every interaction to an audit trail

Usage:
    python chatbot.py

    # Or as a library:
    from chatbot import GovernedChatbot
    bot = GovernedChatbot(agent_id="support-bot", policies=["no_pii", "rate_limit"])
    response = await bot.chat("Hello, how can I reset my password?")
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Import from agent_os — works with just `pip install agent-os-kernel`
from agent_os.stateless import (
    StatelessKernel,
    ExecutionContext,
    ExecutionResult,
    MemoryBackend,
)


# ─── Policy Templates ────────────────────────────────────────────

CHATBOT_POLICIES = {
    "no_pii": {
        "blocked_patterns": [
            "ssn", "social_security", "credit_card",
            "password", "secret", "api_key",
        ]
    },
    "safe_content": {
        "blocked_patterns": [
            "hack", "exploit", "jailbreak",
            "ignore previous instructions",
        ]
    },
    "rate_limit": {
        # Custom: handled by RateLimiter below
        "max_requests_per_minute": 20,
        "max_tokens_per_request": 500,
    },
}


# ─── Rate Limiter ─────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter for chat requests."""

    def __init__(self, max_per_minute: int = 20):
        self.max_per_minute = max_per_minute
        self._timestamps: List[datetime] = []

    def check(self) -> bool:
        """Return True if request is allowed."""
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - 60
        self._timestamps = [t for t in self._timestamps if t.timestamp() > cutoff]
        if len(self._timestamps) >= self.max_per_minute:
            return False
        self._timestamps.append(now)
        return True

    @property
    def remaining(self) -> int:
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - 60
        active = [t for t in self._timestamps if t.timestamp() > cutoff]
        return max(0, self.max_per_minute - len(active))


# ─── Conversation Memory ─────────────────────────────────────────

@dataclass
class ConversationTurn:
    role: str  # "user" or "assistant"
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ConversationMemory:
    """Sliding-window conversation memory."""

    turns: List[ConversationTurn] = field(default_factory=list)
    max_turns: int = 50

    def add(self, role: str, content: str) -> None:
        self.turns.append(ConversationTurn(role=role, content=content))
        if len(self.turns) > self.max_turns:
            self.turns = self.turns[-self.max_turns:]

    def to_context(self) -> List[Dict[str, str]]:
        """Export as LLM-compatible message list."""
        return [{"role": t.role, "content": t.content} for t in self.turns]

    def summary(self) -> str:
        return f"{len(self.turns)} turns, last: {self.turns[-1].content[:50] if self.turns else 'empty'}..."


# ─── Audit Logger ─────────────────────────────────────────────────

@dataclass
class AuditEntry:
    timestamp: str
    agent_id: str
    action: str
    input_hash: str
    policy_result: str
    response_length: int


class AuditLog:
    """Append-only audit log for chatbot interactions."""

    def __init__(self):
        self.entries: List[AuditEntry] = []

    def log(self, agent_id: str, action: str, user_input: str, policy_result: str, response_length: int = 0) -> None:
        self.entries.append(AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            action=action,
            input_hash=hashlib.sha256(user_input.encode()).hexdigest()[:16],
            policy_result=policy_result,
            response_length=response_length,
        ))

    def export(self) -> List[Dict]:
        return [
            {
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "action": e.action,
                "input_hash": e.input_hash,
                "policy_result": e.policy_result,
                "response_length": e.response_length,
            }
            for e in self.entries
        ]


# ─── Governed Chatbot ─────────────────────────────────────────────

class GovernedChatbot:
    """
    A chatbot governed by Agent OS policies.

    Features:
    - Content policy enforcement (PII, harmful content)
    - Rate limiting
    - Conversation memory (sliding window)
    - Full audit trail
    - Pluggable response generation

    Example:
        bot = GovernedChatbot(agent_id="support-bot")
        response = await bot.chat("How do I reset my password?")
        print(response)

        # Check audit
        print(bot.audit.export())
    """

    def __init__(
        self,
        agent_id: str = "governed-chatbot",
        policies: Optional[List[str]] = None,
        max_memory_turns: int = 50,
        rate_limit: int = 20,
        response_fn: Optional[Any] = None,
    ):
        self.agent_id = agent_id
        self.policy_names = policies or ["no_pii", "safe_content", "rate_limit"]

        # Kernel with chatbot-specific policies
        self.kernel = StatelessKernel(policies=CHATBOT_POLICIES)
        self.memory = ConversationMemory(max_turns=max_memory_turns)
        self.rate_limiter = RateLimiter(max_per_minute=rate_limit)
        self.audit = AuditLog()
        self._response_fn = response_fn

    async def chat(self, user_input: str) -> str:
        """
        Process a user message through the governance pipeline.

        Steps:
        1. Rate limit check
        2. Policy enforcement (PII, content safety)
        3. Memory update
        4. Response generation
        5. Output policy check
        6. Audit logging
        """
        # 1. Rate limit
        if not self.rate_limiter.check():
            self.audit.log(self.agent_id, "chat", user_input, "RATE_LIMITED")
            return "⚠️ Rate limit exceeded. Please wait a moment before sending another message."

        # 2. Policy check on input
        context = ExecutionContext(
            agent_id=self.agent_id,
            policies=self.policy_names,
            history=[t.__dict__ for t in self.memory.turns[-5:]],
        )

        result = await self.kernel.execute(
            action="chat",
            params={"message": user_input},
            context=context,
        )

        if not result.success:
            self.audit.log(self.agent_id, "chat", user_input, f"BLOCKED: {result.error}")
            return f"🚫 Message blocked by policy: {result.error}"

        # 3. Add to memory
        self.memory.add("user", user_input)

        # 4. Generate response
        if self._response_fn:
            response = await self._response_fn(user_input, self.memory.to_context())
        else:
            response = self._default_response(user_input)

        # 5. Policy check on output
        output_result = await self.kernel.execute(
            action="chat_response",
            params={"message": response},
            context=context,
        )

        if not output_result.success:
            response = "I apologize, but I cannot provide that response due to content policy."
            self.audit.log(self.agent_id, "chat_response", user_input, "OUTPUT_BLOCKED")
        else:
            self.audit.log(self.agent_id, "chat", user_input, "ALLOWED", len(response))

        # 6. Add response to memory
        self.memory.add("assistant", response)

        return response

    def _default_response(self, user_input: str) -> str:
        """Simple rule-based response (replace with LLM in production)."""
        lower = user_input.lower()

        if any(w in lower for w in ["hello", "hi", "hey"]):
            return "Hello! I'm a governed chatbot. How can I help you today?"
        elif "password" in lower and "reset" in lower:
            return ("To reset your password, go to Settings → Security → Reset Password. "
                    "You'll receive a confirmation email.")
        elif "help" in lower:
            return ("I can help with account management, billing, and general questions. "
                    "What would you like to know?")
        elif "status" in lower:
            return "All systems are operational. No incidents reported."
        elif "bye" in lower or "thanks" in lower:
            return "You're welcome! Have a great day."
        else:
            return (f"I received your message about '{user_input[:50]}'. "
                    "Let me look into that for you.")

    def get_stats(self) -> Dict[str, Any]:
        """Get chatbot statistics."""
        return {
            "agent_id": self.agent_id,
            "conversation_turns": len(self.memory.turns),
            "audit_entries": len(self.audit.entries),
            "rate_limit_remaining": self.rate_limiter.remaining,
            "policies": self.policy_names,
        }


# ─── Interactive CLI ──────────────────────────────────────────────

async def main():
    """Run an interactive governed chatbot session."""
    print("=" * 60)
    print("  Governed Chatbot with Memory — Agent OS Example")
    print("  Policies: no_pii, safe_content, rate_limit (20/min)")
    print("=" * 60)
    print()
    print("Type your messages below. Commands:")
    print("  /stats  — Show chatbot stats")
    print("  /audit  — Show audit log")
    print("  /memory — Show conversation memory")
    print("  /quit   — Exit")
    print()

    bot = GovernedChatbot()

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input:
            continue

        if user_input == "/quit":
            break
        elif user_input == "/stats":
            stats = bot.get_stats()
            for k, v in stats.items():
                print(f"  {k}: {v}")
            continue
        elif user_input == "/audit":
            for entry in bot.audit.export():
                print(f"  [{entry['timestamp'][:19]}] {entry['action']}: {entry['policy_result']}")
            if not bot.audit.entries:
                print("  (no entries yet)")
            continue
        elif user_input == "/memory":
            for turn in bot.memory.turns[-10:]:
                print(f"  {turn.role}: {turn.content[:80]}")
            if not bot.memory.turns:
                print("  (empty)")
            continue

        response = await bot.chat(user_input)
        print(f"Bot: {response}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
