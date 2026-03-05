# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Self-Evolving Agent POC

This module implements a self-evolving agent that:
1. Receives queries and attempts to solve them using tools
2. Evaluates its own performance using an LLM reflection system
3. Evolves its system instructions based on critique when performance is below threshold
4. Retries with improved instructions

Additionally supports a decoupled mode:
- DoerAgent: Synchronous execution with telemetry emission (no learning)
- SelfEvolvingAgent: Legacy synchronous learning mode (for backward compatibility)
"""

import json
import os
import ast
import operator
import time
import random
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import telemetry if available (optional dependency)
try:
    from telemetry import EventStream, TelemetryEvent
    TELEMETRY_AVAILABLE = True
except ImportError:
    TELEMETRY_AVAILABLE = False

# Import prioritization framework if available (optional dependency)
try:
    from prioritization import PrioritizationFramework
    PRIORITIZATION_AVAILABLE = True
except ImportError:
    PRIORITIZATION_AVAILABLE = False


class MemorySystem:
    """Manages the agent's system instructions stored in JSON."""
    
    def __init__(self, memory_file: str = "system_instructions.json"):
        self.memory_file = memory_file
        self.instructions = self.load_instructions()
    
    def load_instructions(self) -> Dict[str, Any]:
        """Load system instructions from JSON file."""
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            except (json.JSONDecodeError, IOError):
                pass
        # Default instructions
        return {
            "version": 1,
            "instructions": "You are a helpful AI assistant.",
            "improvements": []
        }
    
    def save_instructions(self, instructions: Dict[str, Any]) -> None:
        """Save system instructions to JSON file."""
        with open(self.memory_file, 'w') as f:
            json.dump(instructions, f, indent=2)
        self.instructions = instructions
    
    def get_system_prompt(self) -> str:
        """Get the current system instructions as a prompt."""
        return self.instructions.get("instructions", "")
    
    def update_instructions(self, new_instructions: str, critique: str, *,
                           query: Optional[str] = None, response: Optional[str] = None) -> None:
        """
        Update instructions with new version and log the improvement.
        
        Args:
            new_instructions: New system instructions
            critique: Critique that prompted the improvement
            query: Optional query that caused the failure (for upgrade purge)
            response: Optional agent response that failed (for upgrade purge)
        """
        self.instructions["version"] = self.instructions.get("version", 0) + 1
        self.instructions["instructions"] = new_instructions
        
        improvement_entry = {
            "version": self.instructions["version"],
            "timestamp": datetime.now().isoformat(),
            "critique": critique
        }
        
        # Store query and response for upgrade purge strategy
        if query:
            improvement_entry["query"] = query
        if response:
            improvement_entry["response"] = response
        
        self.instructions["improvements"].append(improvement_entry)
        self.save_instructions(self.instructions)


class AgentTools:
    """Simple tools the agent can use."""
    
    @staticmethod
    def calculate(expression: str) -> str:
        """Safely evaluate a mathematical expression using AST parsing."""
        # Safe mathematical operators
        operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow,
            ast.USub: operator.neg,
        }
        
        def eval_node(node):
            if isinstance(node, ast.Constant):  # Python 3.8+
                return node.value
            elif isinstance(node, ast.Num):  # Fallback for older Python
                return node.n
            elif isinstance(node, ast.BinOp):
                left = eval_node(node.left)
                right = eval_node(node.right)
                return operators[type(node.op)](left, right)
            elif isinstance(node, ast.UnaryOp):
                operand = eval_node(node.operand)
                return operators[type(node.op)](operand)
            else:
                raise ValueError(f"Unsupported operation: {type(node).__name__}")
        
        try:
            # Parse the expression
            tree = ast.parse(expression, mode='eval')
            result = eval_node(tree.body)
            return f"Result: {result}"
        except (ValueError, KeyError, SyntaxError, TypeError) as e:
            return f"Error: Invalid mathematical expression - {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def get_current_time() -> str:
        """Get the current time."""
        return f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    @staticmethod
    def string_length(text: str) -> str:
        """Get the length of a string."""
        return f"Length: {len(text)}"
    
    @staticmethod
    def get_available_tools() -> str:
        """List available tools."""
        return """Available tools:
1. calculate(expression) - Evaluate mathematical expressions
2. get_current_time() - Get current date and time
3. string_length(text) - Get length of a string
"""


# Constants for circuit breaker integration
CIRCUIT_BREAKER_EVAL_PROBABILITY = 0.1  # Evaluate circuit breaker 10% of the time


class DoerAgent:
    """
    The "Doer" - Synchronous execution agent.
    
    Executes tasks with read-only access to the Wisdom Database.
    Emits telemetry to an event stream for offline learning.
    Does NOT perform reflection or evolution during execution.
    
    Optionally supports circuit breaker for A/B testing different agent versions.
    Publishes an OpenAgent Definition (OAD) metadata manifest.
    """
    
    def __init__(self,
                 wisdom_file: str = "system_instructions.json",
                 stream_file: str = "telemetry_events.jsonl",
                 enable_telemetry: bool = True,
                 enable_prioritization: bool = True,
                 enable_intent_detection: bool = True,
                 enable_circuit_breaker: bool = False,
                 circuit_breaker_config_file: Optional[str] = None,
                 enable_constraint_engine: bool = False,
                 constraint_engine_config: Optional[Dict[str, Any]] = None,
                 enable_metadata: bool = True,
                 manifest_file: str = "agent_manifest.json"):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.wisdom = MemorySystem(wisdom_file)  # Read-only access
        self.tools = AgentTools()
        self.enable_telemetry = enable_telemetry and TELEMETRY_AVAILABLE
        self.enable_prioritization = enable_prioritization and PRIORITIZATION_AVAILABLE
        self.enable_intent_detection = enable_intent_detection
        self.enable_circuit_breaker = enable_circuit_breaker
        self.enable_constraint_engine = enable_constraint_engine
        self.enable_metadata = enable_metadata
        
        if self.enable_telemetry:
            self.event_stream = EventStream(stream_file)
        
        if self.enable_prioritization:
            self.prioritization = PrioritizationFramework()
        
        # OpenAgent Definition (OAD) metadata system
        if self.enable_metadata:
            try:
                from agent_metadata import AgentMetadataManager, create_default_manifest
                self.metadata_manager = AgentMetadataManager(manifest_file)
                
                # Load or create default manifest
                if not self.metadata_manager.load_manifest():
                    metadata = create_default_manifest(
                        agent_id="doer-agent",
                        name="Doer Agent (Self-Evolving)",
                        version="1.0.0"
                    )
                    self.metadata_manager.save_manifest(metadata)
            except ImportError as e:
                print(f"Warning: Metadata system disabled - ImportError: {e}")
                self.enable_metadata = False
                self.metadata_manager = None
            except Exception as e:
                print(f"Warning: Metadata system disabled - {type(e).__name__}: {e}")
                self.enable_metadata = False
                self.metadata_manager = None
        
        # Intent detection
        if self.enable_intent_detection:
            try:
                from intent_detection import IntentDetector
                self.intent_detector = IntentDetector()
            except ImportError as e:
                print(f"Warning: Intent detection disabled - ImportError: {e}")
                self.enable_intent_detection = False
                self.intent_detector = None
            except Exception as e:
                print(f"Warning: Intent detection disabled - {type(e).__name__}: {e}")
                self.enable_intent_detection = False
                self.intent_detector = None
        
        # Circuit breaker for A/B testing
        if self.enable_circuit_breaker:
            try:
                from circuit_breaker import CircuitBreakerController, CircuitBreakerConfig
                
                if circuit_breaker_config_file and os.path.exists(circuit_breaker_config_file):
                    import json
                    with open(circuit_breaker_config_file, 'r') as f:
                        config_data = json.load(f)
                    config = CircuitBreakerConfig(**config_data)
                else:
                    config = CircuitBreakerConfig()
                
                self.circuit_breaker = CircuitBreakerController(config=config)
            except ImportError as e:
                print(f"Warning: Circuit breaker disabled - ImportError: {e}")
                self.enable_circuit_breaker = False
                self.circuit_breaker = None
            except Exception as e:
                print(f"Warning: Circuit breaker disabled - {type(e).__name__}: {e}")
                self.enable_circuit_breaker = False
                self.circuit_breaker = None
        
        # Constraint engine (logic firewall)
        if self.enable_constraint_engine:
            try:
                from constraint_engine import create_default_engine
                
                if constraint_engine_config:
                    self.constraint_engine = create_default_engine(**constraint_engine_config)
                else:
                    self.constraint_engine = create_default_engine()
            except ImportError as e:
                print(f"Warning: Constraint engine disabled - ImportError: {e}")
                self.enable_constraint_engine = False
                self.constraint_engine = None
            except Exception as e:
                print(f"Warning: Constraint engine disabled - {type(e).__name__}: {e}")
                self.enable_constraint_engine = False
                self.constraint_engine = None
        
        # Model configuration
        self.agent_model = os.getenv("AGENT_MODEL", "gpt-4o-mini")
    
    def execute_tool(self, tool_name: str, *args) -> str:
        """Execute a tool by name with error handling."""
        if not hasattr(self.tools, tool_name):
            return f"Error: Tool '{tool_name}' not found"
        
        try:
            return getattr(self.tools, tool_name)(*args)
        except Exception as e:
            return f"Error executing tool '{tool_name}': {str(e)}"
    
    def validate_action_plan(self, plan: Dict[str, Any], verbose: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate an action plan through the constraint engine (logic firewall).
        
        Args:
            plan: Action plan to validate with keys:
                - action_type: Type of action (e.g., "sql_query", "email", "file_operation")
                - action_data: Action-specific data
            verbose: Print validation details
        
        Returns:
            (approved, reason) tuple where:
                - approved: Whether the plan passed validation
                - reason: Reason for rejection if not approved
        """
        if not self.enable_constraint_engine:
            return True, None
        
        result = self.constraint_engine.validate_plan(plan, verbose=verbose)
        
        if result.approved:
            return True, None
        else:
            # Collect violation messages
            violation_messages = [v.message for v in result.get_blocking_violations()]
            reason = "; ".join(violation_messages)
            return False, reason
    
    def act(self, query: str, user_id: Optional[str] = None, 
            version_override: Optional[str] = None) -> Tuple[str, str]:
        """
        Agent attempts to solve the query using current wisdom.
        Uses prioritization framework to rank context by importance.
        
        Args:
            query: User's query
            user_id: Optional user identifier for personalization
            version_override: Optional version to use ("old" or "new"), 
                            overrides circuit breaker decision
        
        Returns:
            (response, version) tuple where version is "old" or "new"
        """
        # Determine which version to use
        version = "old"  # Default
        
        if self.enable_circuit_breaker and version_override is None:
            # Let circuit breaker decide based on traffic split
            use_new = self.circuit_breaker.should_use_new_version(request_id=user_id)
            version = "new" if use_new else "old"
        elif version_override:
            version = version_override
        
        system_prompt = self.wisdom.get_system_prompt()
        
        # Use prioritization framework if available
        if self.enable_prioritization:
            prioritized_context = self.prioritization.get_prioritized_context(
                query=query,
                global_wisdom=system_prompt,
                user_id=user_id,
                verbose=False
            )
            system_prompt = prioritized_context.build_system_prompt()
        
        # Version is tracked internally but doesn't modify the actual system prompt
        # In production, different versions might use different models, prompts, or tools
        # For this POC, both versions use the same prompt (version is just for A/B testing tracking)
        
        # Add tool information to the system prompt
        full_system_prompt = f"{system_prompt}\n\n{self.tools.get_available_tools()}"
        full_system_prompt += "\nIf you need to use a tool, explain which tool you would use and why."
        
        messages = [
            {"role": "system", "content": full_system_prompt},
            {"role": "user", "content": query}
        ]
        
        try:
            response = self.client.chat.completions.create(
                model=self.agent_model,
                messages=messages,
                temperature=0.7
            )
            return response.choices[0].message.content, version
        except Exception as e:
            return f"Error executing agent: {str(e)}", version
    
    def _emit_telemetry(self, event_type: str, query: str, 
                       agent_response: Optional[str] = None,
                       success: Optional[bool] = None,
                       user_feedback: Optional[str] = None,
                       user_id: Optional[str] = None,
                       conversation_id: Optional[str] = None,
                       turn_number: Optional[int] = None,
                       intent_type: Optional[str] = None,
                       intent_confidence: Optional[float] = None) -> None:
        """Emit telemetry event to the stream."""
        if not self.enable_telemetry:
            return
        
        metadata = {"user_id": user_id} if user_id else None
        
        event = TelemetryEvent(
            event_type=event_type,
            timestamp=datetime.now().isoformat(),
            query=query,
            agent_response=agent_response,
            success=success,
            user_feedback=user_feedback,
            instructions_version=self.wisdom.instructions['version'],
            metadata=metadata,
            conversation_id=conversation_id,
            turn_number=turn_number,
            intent_type=intent_type,
            intent_confidence=intent_confidence
        )
        self.event_stream.emit(event)
    
    def _emit_signal(self, signal_type: str, query: str, agent_response: Optional[str],
                    success: bool, user_id: Optional[str], 
                    signal_context: Dict[str, Any], verbose: bool) -> None:
        """
        Helper method to emit a signal event to the stream.
        Reduces code duplication across signal emission methods.
        """
        if not self.enable_telemetry:
            return
        
        metadata = dict(signal_context)
        if user_id:
            metadata["user_id"] = user_id
        
        event = TelemetryEvent(
            event_type=f"signal_{signal_type}",
            timestamp=datetime.now().isoformat(),
            query=query,
            agent_response=agent_response,
            success=success,
            instructions_version=self.wisdom.instructions['version'],
            metadata=metadata,
            signal_type=signal_type,
            signal_context=signal_context
        )
        self.event_stream.emit(event)
        
        if verbose:
            print("[TELEMETRY] Signal emitted to stream")
    
    def run(self, query: str, verbose: bool = True, 
            user_feedback: Optional[str] = None,
            user_id: Optional[str] = None,
            conversation_id: Optional[str] = None,
            turn_number: Optional[int] = None) -> Dict[str, Any]:
        """
        Execute query and emit telemetry.
        No reflection or evolution - just execution.
        
        Args:
            query: User's query
            verbose: Print execution details
            user_feedback: Optional user feedback
            user_id: Optional user identifier for personalization
            conversation_id: Optional conversation identifier for tracking multi-turn conversations
            turn_number: Optional turn number within the conversation (1-indexed)
        """
        # Detect intent on first turn
        intent_type = None
        intent_confidence = None
        
        if self.enable_intent_detection and turn_number == 1:
            if verbose:
                print("="*60)
                print("DOER AGENT: Executing Task with Intent Detection")
                print("="*60)
            
            intent_result = self.intent_detector.detect_intent(query, verbose=verbose)
            intent_type = intent_result["intent"]
            intent_confidence = intent_result["confidence"]
        elif verbose:
            print("="*60)
            print("DOER AGENT: Executing Task")
            print("="*60)
        
        if verbose:
            print(f"Query: {query}")
            print(f"User ID: {user_id or 'Anonymous'}")
            print(f"Conversation ID: {conversation_id or 'N/A'}")
            print(f"Turn Number: {turn_number or 'N/A'}")
            print(f"Wisdom Version: {self.wisdom.instructions['version']}")
            if self.enable_prioritization:
                print("[PRIORITIZATION] Enabled - using ranked context")
            if self.enable_circuit_breaker:
                status = self.circuit_breaker.get_status()
                print(f"[CIRCUIT BREAKER] Phase: {status['current_phase']}, State: {status['state']}")
        
        # Record start time for latency tracking
        start_time = time.time()
        
        # Emit task start event
        self._emit_telemetry(
            "task_start", 
            query, 
            user_id=user_id,
            conversation_id=conversation_id,
            turn_number=turn_number,
            intent_type=intent_type,
            intent_confidence=intent_confidence
        )
        
        # ACT: Execute the query with prioritization and circuit breaker
        if verbose:
            print("\n[EXECUTING] Processing query...")
        
        agent_response, version = self.act(query, user_id=user_id)
        
        # Calculate latency
        latency_ms = (time.time() - start_time) * 1000
        
        if verbose:
            print(f"Response: {agent_response}")
            if self.enable_circuit_breaker:
                print(f"Version Used: {version.upper()}, Latency: {latency_ms:.0f}ms")
        
        # Record execution in circuit breaker if enabled
        if self.enable_circuit_breaker:
            # For simplicity, we consider any non-error response as success
            success = not agent_response.startswith("Error")
            self.circuit_breaker.record_execution(version, success, latency_ms)
            
            # Periodically evaluate and decide on rollout progression
            # In production, this might be done by a separate process
            if random.random() < CIRCUIT_BREAKER_EVAL_PROBABILITY:
                self.circuit_breaker.evaluate_and_decide(verbose=False)
        
        # Update agent metadata trust score if enabled
        if self.enable_metadata and self.metadata_manager:
            success = not agent_response.startswith("Error")
            metadata = self.metadata_manager.get_manifest()
            if metadata:
                metadata.update_trust_score(success=success, latency_ms=latency_ms)
                self.metadata_manager.save_manifest(metadata)
        
        # Emit task completion event
        self._emit_telemetry(
            "task_complete",
            query,
            agent_response=agent_response,
            success=True,
            user_feedback=user_feedback,
            user_id=user_id,
            conversation_id=conversation_id,
            turn_number=turn_number,
            intent_type=intent_type,
            intent_confidence=intent_confidence
        )
        
        if verbose:
            print("\n[TELEMETRY] Event emitted to stream")
        
        result = {
            "query": query,
            "response": agent_response,
            "instructions_version": self.wisdom.instructions['version'],
            "telemetry_emitted": self.enable_telemetry,
            "prioritization_enabled": self.enable_prioritization,
            "conversation_id": conversation_id,
            "turn_number": turn_number,
            "intent_type": intent_type,
            "intent_confidence": intent_confidence
        }
        
        # Add circuit breaker info if enabled
        if self.enable_circuit_breaker:
            result["circuit_breaker_enabled"] = True
            result["version_used"] = version
            result["latency_ms"] = latency_ms
        
        return result
    
    def emit_undo_signal(self, query: str, agent_response: str, 
                        user_id: Optional[str] = None,
                        undo_action: Optional[str] = None,
                        verbose: bool = True) -> None:
        """
        Emit an "Undo" signal - Critical Failure.
        
        This is called when a user reverses an agent action (e.g., Ctrl+Z, revert code).
        This is the loudest "Thumbs Down" possible.
        
        Args:
            query: Original query
            agent_response: Agent's response that was undone
            user_id: Optional user identifier
            undo_action: Description of what was undone
            verbose: Print signal details
        """
        if verbose:
            print("\n" + "="*60)
            print("🚨 UNDO SIGNAL DETECTED - Critical Failure")
            print("="*60)
            print(f"User reversed agent action: {undo_action or 'Not specified'}")
        
        self._emit_signal(
            signal_type="undo",
            query=query,
            agent_response=agent_response,
            success=False,
            user_id=user_id,
            signal_context={"undo_action": undo_action},
            verbose=verbose
        )
    
    def emit_abandonment_signal(self, query: str, agent_response: Optional[str] = None,
                                user_id: Optional[str] = None,
                                interaction_count: int = 0,
                                last_interaction_time: Optional[str] = None,
                                verbose: bool = True) -> None:
        """
        Emit an "Abandonment" signal - Loss.
        
        This is called when a user starts a workflow but stops responding halfway
        without reaching a resolution. This means we lost them.
        
        Args:
            query: Original query
            agent_response: Last agent response before abandonment
            user_id: Optional user identifier
            interaction_count: Number of interactions before abandonment
            last_interaction_time: Timestamp of last interaction
            verbose: Print signal details
        """
        if verbose:
            print("\n" + "="*60)
            print("⚠️ ABANDONMENT SIGNAL DETECTED - Loss")
            print("="*60)
            print(f"User abandoned workflow after {interaction_count} interactions")
        
        self._emit_signal(
            signal_type="abandonment",
            query=query,
            agent_response=agent_response,
            success=False,
            user_id=user_id,
            signal_context={
                "interaction_count": interaction_count,
                "last_interaction_time": last_interaction_time
            },
            verbose=verbose
        )
    
    def emit_acceptance_signal(self, query: str, agent_response: str,
                              user_id: Optional[str] = None,
                              next_task: Optional[str] = None,
                              time_to_next_task: Optional[float] = None,
                              verbose: bool = True) -> None:
        """
        Emit an "Acceptance" signal - Success.
        
        This is called when a user takes the output and moves to the next task
        without follow-up questions. This means we won.
        
        Args:
            query: Original query
            agent_response: Agent's response that was accepted
            user_id: Optional user identifier
            next_task: Description of the next task user moved to
            time_to_next_task: Time in seconds from response to next task
            verbose: Print signal details
        """
        if verbose:
            print("\n" + "="*60)
            print("✅ ACCEPTANCE SIGNAL DETECTED - Success")
            print("="*60)
            print(f"User accepted output and moved to: {next_task or 'next task'}")
        
        self._emit_signal(
            signal_type="acceptance",
            query=query,
            agent_response=agent_response,
            success=True,
            user_id=user_id,
            signal_context={
                "next_task": next_task,
                "time_to_next_task": time_to_next_task
            },
            verbose=verbose
        )
    
    def get_metadata_manifest(self) -> Optional[Dict[str, Any]]:
        """
        Get the agent's OpenAgent Definition (OAD) metadata manifest.
        
        Returns the complete metadata including capabilities, constraints,
        IO contract, and trust score.
        
        This is the "USB Port" for AI - a standard interface definition
        that allows agents to be discovered, understood, and composed.
        """
        if not self.enable_metadata or not self.metadata_manager:
            return None
        
        metadata = self.metadata_manager.get_manifest()
        return metadata.to_dict() if metadata else None
    
    def publish_manifest(self) -> Optional[Dict[str, Any]]:
        """
        Publish the agent's metadata manifest.
        
        In a real system, this would register the agent in a marketplace
        or registry for discovery by other agents or systems.
        """
        if not self.enable_metadata or not self.metadata_manager:
            return None
        
        try:
            return self.metadata_manager.publish_manifest()
        except ValueError as e:
            print(f"Error publishing manifest: {e}")
            return None


class SelfEvolvingAgent:
    """
    Legacy self-evolving agent with synchronous reflection and evolution.
    Kept for backward compatibility.
    """
    
    def __init__(self, 
                 memory_file: str = "system_instructions.json",
                 score_threshold: float = 0.8,
                 max_retries: int = 3):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.memory = MemorySystem(memory_file)
        self.tools = AgentTools()
        self.score_threshold = score_threshold
        self.max_retries = max_retries
        
        # Model configuration
        self.agent_model = os.getenv("AGENT_MODEL", "gpt-4o-mini")
        self.reflection_model = os.getenv("REFLECTION_MODEL", "gpt-4o-mini")
        self.evolution_model = os.getenv("EVOLUTION_MODEL", "gpt-4o-mini")
    
    def execute_tool(self, tool_name: str, *args) -> str:
        """Execute a tool by name."""
        if hasattr(self.tools, tool_name):
            return getattr(self.tools, tool_name)(*args)
        return f"Error: Tool '{tool_name}' not found"
    
    def act(self, query: str) -> str:
        """
        Agent attempts to solve the query using its current system instructions.
        """
        system_prompt = self.memory.get_system_prompt()
        
        # Add tool information to the system prompt
        full_system_prompt = f"{system_prompt}\n\n{self.tools.get_available_tools()}"
        full_system_prompt += "\nIf you need to use a tool, explain which tool you would use and why."
        
        messages = [
            {"role": "system", "content": full_system_prompt},
            {"role": "user", "content": query}
        ]
        
        try:
            response = self.client.chat.completions.create(
                model=self.agent_model,
                messages=messages,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error executing agent: {str(e)}"
    
    def reflect(self, query: str, agent_response: str) -> Tuple[float, str]:
        """
        Separate LLM call to evaluate the agent's output.
        Returns a score (0-1) and critique.
        """
        reflection_prompt = f"""You are an evaluator assessing an AI agent's response.

User Query: {query}

Agent Response: {agent_response}

Evaluate the response on the following criteria:
1. Correctness: Did the agent answer the question correctly?
2. Completeness: Did the agent provide a complete answer?
3. Clarity: Is the response clear and well-explained?
4. Tool Usage: Did the agent appropriately identify and explain tool usage when needed?

Provide your evaluation as JSON with:
- score: A number between 0 and 1 (0 = poor, 1 = excellent)
- critique: A detailed explanation of what was good and what could be improved

Return ONLY valid JSON in this format:
{{"score": 0.85, "critique": "Your detailed critique here"}}
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.reflection_model,
                messages=[{"role": "user", "content": reflection_prompt}],
                temperature=0.3
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response (handle markdown code blocks)
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(result_text)
            return result["score"], result["critique"]
        except Exception as e:
            print(f"Error in reflection: {str(e)}")
            # Default to low score if reflection fails
            return 0.5, f"Reflection error: {str(e)}"
    
    def evolve(self, critique: str, query: str, agent_response: str) -> str:
        """
        Third LLM call that reads critique and rewrites system instructions.
        """
        current_instructions = self.memory.get_system_prompt()
        
        evolution_prompt = f"""You are a meta-learning system that improves AI agent instructions.

Current System Instructions:
{current_instructions}

Recent Query: {query}
Agent Response: {agent_response}

Evaluation Critique:
{critique}

Your task is to rewrite the system instructions to address the issues identified in the critique.
The new instructions should help the agent perform better on similar queries in the future.

Guidelines:
- Keep the instructions clear and concise
- Add specific guidance to address the critique
- Maintain the helpful and accurate nature of the agent
- Include any necessary improvements for tool usage
- Don't make the instructions overly long or complex

Return ONLY the new system instructions as plain text (no JSON, no formatting):
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.evolution_model,
                messages=[{"role": "user", "content": evolution_prompt}],
                temperature=0.7
            )
            
            new_instructions = response.choices[0].message.content.strip()
            return new_instructions
        except Exception as e:
            print(f"Error in evolution: {str(e)}")
            return current_instructions  # Return unchanged if evolution fails
    
    def run(self, query: str, verbose: bool = True) -> Dict[str, Any]:
        """
        Main loop: Task -> Act -> Reflect -> Evolve -> Retry
        """
        results = {
            "query": query,
            "attempts": []
        }
        
        for attempt in range(self.max_retries):
            if verbose:
                print(f"\n{'='*60}")
                print(f"ATTEMPT {attempt + 1}/{self.max_retries}")
                print(f"{'='*60}")
                print(f"Current Instructions Version: {self.memory.instructions['version']}")
            
            # ACT: Agent tries to solve the query
            if verbose:
                print(f"\n[ACTING] Processing query...")
            agent_response = self.act(query)
            if verbose:
                print(f"Agent Response: {agent_response}")
            
            # REFLECT: Evaluate the response
            if verbose:
                print(f"\n[REFLECTING] Evaluating response...")
            score, critique = self.reflect(query, agent_response)
            if verbose:
                print(f"Score: {score}")
                print(f"Critique: {critique}")
            
            # Store attempt results
            attempt_result = {
                "attempt": attempt + 1,
                "response": agent_response,
                "score": score,
                "critique": critique,
                "instructions_version": self.memory.instructions['version']
            }
            results["attempts"].append(attempt_result)
            
            # Check if score meets threshold
            if score >= self.score_threshold:
                if verbose:
                    print(f"\n[SUCCESS] Score {score} meets threshold {self.score_threshold}")
                results["success"] = True
                results["final_response"] = agent_response
                results["final_score"] = score
                return results
            
            # EVOLVE: If score < threshold and we have retries left
            if attempt < self.max_retries - 1:
                if verbose:
                    print(f"\n[EVOLVING] Score {score} below threshold {self.score_threshold}")
                    print("Rewriting system instructions...")
                
                new_instructions = self.evolve(critique, query, agent_response)
                self.memory.update_instructions(new_instructions, critique, query=query, response=agent_response)
                
                if verbose:
                    print(f"Updated to version {self.memory.instructions['version']}")
                    print(f"New instructions: {new_instructions[:200]}...")
        
        # Max retries reached
        if verbose:
            print(f"\n[EXHAUSTED] Max retries reached. Best score: {max(a['score'] for a in results['attempts'])}")
        
        results["success"] = False
        best_attempt = max(results["attempts"], key=lambda x: x["score"])
        results["final_response"] = best_attempt["response"]
        results["final_score"] = best_attempt["score"]
        return results


def main():
    """Example usage of the self-evolving agent."""
    print("Self-Evolving Agent POC")
    print("=" * 60)
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file with your OpenAI API key")
        return
    
    # Initialize agent
    agent = SelfEvolvingAgent(
        score_threshold=float(os.getenv("SCORE_THRESHOLD", "0.8")),
        max_retries=int(os.getenv("MAX_RETRIES", "3"))
    )
    
    # Example queries
    queries = [
        "What is 15 * 24 + 100?",
        "What is the length of the word 'supercalifragilisticexpialidocious'?",
        "What time is it right now?"
    ]
    
    for i, query in enumerate(queries, 1):
        print(f"\n\n{'#'*60}")
        print(f"QUERY {i}: {query}")
        print(f"{'#'*60}")
        
        results = agent.run(query, verbose=True)
        
        print(f"\n\nFINAL RESULTS:")
        print(f"Success: {results['success']}")
        print(f"Final Score: {results['final_score']}")
        print(f"Total Attempts: {len(results['attempts'])}")
        print(f"Final Response: {results['final_response']}")
        
        # Wait for user input between queries (optional)
        if i < len(queries):
            input("\nPress Enter to continue to next query...")


if __name__ == "__main__":
    main()
