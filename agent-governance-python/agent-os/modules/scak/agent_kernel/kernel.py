# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Self-Correcting Agent Kernel - Main orchestrator.

Implements the Dual-Loop Architecture:
- Loop 1 (Runtime): Constraint Engine (Safety)
- Loop 2 (Offline): Alignment Engine (Quality & Efficiency)
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from .models import (
    AgentFailure, FailureAnalysis, SimulationResult, CorrectionPatch, AgentState,
    AgentOutcome, CompletenessAudit, ClassifiedPatch,
    ToolExecutionTelemetry, NudgeResult
)
from .detector import FailureDetector
from .analyzer import FailureAnalyzer
from .simulator import PathSimulator
from .patcher import AgentPatcher
from .outcome_analyzer import OutcomeAnalyzer
from .completeness_auditor import CompletenessAuditor
from .semantic_purge import SemanticPurge
from .triage import FailureTriage, FixStrategy
from .nudge_mechanism import NudgeMechanism

logger = logging.getLogger(__name__)


class SelfCorrectingAgentKernel:
    """
    Main kernel implementing the Dual-Loop Architecture.
    
    LOOP 1 (Runtime): The Constraint Engine filters for Safety
    LOOP 2 (Offline): The Alignment Engine filters for Quality & Efficiency:
        - Completeness Auditor: Detects "laziness" (give-up signals)
        - Semantic Purge: Manages patch lifecycle (scale by subtraction)
    
    When an agent fails OR gives up:
    1. Detects and classifies the outcome
    2. Analyzes for safety (Loop 1) and competence (Loop 2)
    3. Simulates alternative paths
    4. Patches the agent with classified, lifecycle-managed fixes
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the self-correcting agent kernel with Dual-Loop Architecture.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # LOOP 1: Runtime Safety Components
        self.detector = FailureDetector()
        self.analyzer = FailureAnalyzer()
        self.simulator = PathSimulator()
        self.patcher = AgentPatcher()
        
        # LOOP 2: Offline Alignment Components
        use_semantic_analysis = self.config.get("use_semantic_analysis", True)
        self.outcome_analyzer = OutcomeAnalyzer(use_semantic_analysis=use_semantic_analysis)
        self.completeness_auditor = CompletenessAuditor(
            teacher_model=self.config.get("teacher_model", "o1-preview")
        )
        self.semantic_purge = SemanticPurge()
        self.nudge_mechanism = NudgeMechanism()
        
        # Triage Engine: Decides sync (JIT) vs async (batch) correction
        self.triage = FailureTriage(config=self.config.get("triage_config", {}))
        
        # Background queue for async failures (placeholder for production implementation)
        self.async_failure_queue = []
        
        # Model version tracking for semantic purge
        self.current_model_version = self.config.get("model_version", "gpt-4o")
        
        # Configure logging
        self._setup_logging()
        
        logger.info("=" * 80)
        logger.info("Self-Correcting Agent Kernel initialized (Dual-Loop Architecture)")
        logger.info(f"  Loop 1 (Runtime): Constraint Engine (Safety)")
        logger.info(f"  Loop 2 (Offline): Alignment Engine (Quality & Efficiency)")
        logger.info(f"    - Completeness Auditor: {self.completeness_auditor.teacher_model}")
        logger.info(f"    - Semantic Purge: Active")
        logger.info(f"    - Failure Triage: Active (Sync/Async routing)")
        logger.info(f"    - Semantic Analysis: {use_semantic_analysis}")
        logger.info(f"    - Nudge Mechanism: Active")
        logger.info(f"  Model Version: {self.current_model_version}")
        logger.info("=" * 80)
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = self.config.get("log_level", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def handle_failure(
        self,
        agent_id: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
        auto_patch: bool = True,
        user_prompt: Optional[str] = None,
        chain_of_thought: Optional[List[str]] = None,
        failed_action: Optional[Dict[str, Any]] = None,
        user_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle an agent failure through the full self-correction pipeline.
        
        Enhanced to support full trace capture, cognitive diagnosis, and triage routing.
        
        This is the main entry point when an agent fails in production.
        
        Args:
            agent_id: Identifier of the failed agent
            error_message: Error message from the failure
            context: Additional context about the failure
            stack_trace: Optional stack trace
            auto_patch: Whether to automatically apply the patch (default: True)
            user_prompt: Original user prompt (for full trace)
            chain_of_thought: Agent's reasoning steps (for cognitive analysis)
            failed_action: The specific action that failed
            user_metadata: User metadata (e.g., VIP status) for triage decisions
            
        Returns:
            Dictionary containing the results of the self-correction process
        """
        logger.info(f"=" * 80)
        logger.info(f"AGENT FAILURE DETECTED - Starting enhanced self-correction process")
        logger.info(f"Agent ID: {agent_id}")
        logger.info(f"Error: {error_message}")
        logger.info(f"=" * 80)
        
        # Step 0: Triage - Decide sync (JIT) or async (batch) correction strategy
        if user_prompt:
            tool_name = context.get("action") if context else None
            
            # Prepare enhanced context for triage including failed_action and chain_of_thought
            triage_context = dict(context) if context else {}
            if failed_action:
                triage_context["failed_action"] = failed_action
            if chain_of_thought:
                triage_context["chain_of_thought"] = chain_of_thought
            
            strategy = self.triage.decide_strategy(
                prompt=user_prompt,
                tool_name=tool_name,
                user_metadata=user_metadata,
                context=triage_context
            )
            
            logger.info(f"[TRIAGE] Decision: {strategy.value}")
            
            if strategy == FixStrategy.ASYNC_BATCH:
                logger.info(">> Non-Critical Failure. Queuing for async optimization.")
                logger.info(">> Returning error to user immediately (low latency).")
                
                # Add to async queue for later processing
                self.async_failure_queue.append({
                    "agent_id": agent_id,
                    "error_message": error_message,
                    "context": context,
                    "stack_trace": stack_trace,
                    "user_prompt": user_prompt,
                    "chain_of_thought": chain_of_thought,
                    "failed_action": failed_action,
                    "timestamp": datetime.utcnow()
                })
                
                return {
                    "success": False,
                    "strategy": strategy,
                    "message": "Non-critical failure queued for async correction",
                    "queued": True,
                    "error": error_message
                }
            else:
                logger.info(">> Critical Failure Detected. Entering Self-Correction Mode (User Waiting)...")
                logger.info(">> High latency path - fixing immediately for reliability.")
        
        # Step 1: Detect and classify failure with full trace
        logger.info("[1/5] Detecting and classifying failure (capturing full trace)...")
        failure = self.detector.detect_failure(
            agent_id=agent_id,
            error_message=error_message,
            context=context,
            stack_trace=stack_trace,
            user_prompt=user_prompt,
            chain_of_thought=chain_of_thought,
            failed_action=failed_action
        )
        
        # Step 2: Deep cognitive analysis
        logger.info("[2/5] Analyzing failure (identifying cognitive glitches)...")
        failure_history = self.detector.get_failure_history(agent_id=agent_id)
        similar_failures = self.analyzer.find_similar_failures(failure, failure_history)
        analysis = self.analyzer.analyze(failure, similar_failures)
        
        # Generate cognitive diagnosis if trace available
        diagnosis = None
        if failure.failure_trace:
            logger.info("      → Performing deep cognitive analysis...")
            diagnosis = self.analyzer.diagnose_cognitive_glitch(failure)
            logger.info(f"      → Cognitive glitch: {diagnosis.cognitive_glitch.value}")
        
        # Step 3: Simulate alternative path
        logger.info("[3/5] Simulating alternative path...")
        simulation = self.simulator.simulate(analysis)
        
        # Step 4: Counterfactual simulation with Shadow Agent
        shadow_result = None
        if diagnosis and failure.failure_trace:
            logger.info("[4/5] Running counterfactual simulation (Shadow Agent)...")
            shadow_result = self.simulator.simulate_counterfactual(diagnosis, failure)
            logger.info(f"      → Shadow agent verified: {shadow_result.verified}")
        else:
            logger.info("[4/5] Skipping Shadow Agent (no trace available)")
        
        if not simulation.success and (not shadow_result or not shadow_result.verified):
            logger.warning("Simulation did not produce a viable alternative path")
            return {
                "success": False,
                "failure": failure,
                "analysis": analysis,
                "diagnosis": diagnosis,
                "simulation": simulation,
                "shadow_result": shadow_result,
                "patch": None,
                "message": "Could not find a viable alternative path"
            }
        
        # Step 5: Create and optionally apply patch
        logger.info("[5/5] Creating correction patch (The Optimizer)...")
        patch = self.patcher.create_patch(
            agent_id, analysis, simulation, diagnosis, shadow_result
        )
        
        # Classify patch for lifecycle management (Semantic Purge integration)
        classified_patch = self.semantic_purge.register_patch(
            patch=patch,
            current_model_version=self.current_model_version
        )
        logger.info(f"      → Patch classified as: {classified_patch.decay_type.value}")
        
        patch_applied = False
        if auto_patch:
            logger.info("Auto-patching enabled, applying patch...")
            patch_applied = self.patcher.apply_patch(patch)
        else:
            logger.info("Auto-patching disabled, patch created but not applied")
        
        logger.info(f"=" * 80)
        logger.info(f"SELF-CORRECTION COMPLETE")
        logger.info(f"Patch ID: {patch.patch_id}")
        logger.info(f"Patch Type: {patch.patch_type}")
        logger.info(f"Decay Type: {classified_patch.decay_type.value}")
        logger.info(f"Purge on Upgrade: {classified_patch.should_purge_on_upgrade}")
        if diagnosis:
            logger.info(f"Cognitive Glitch: {diagnosis.cognitive_glitch.value}")
        logger.info(f"Patch Applied: {patch_applied}")
        logger.info(f"Expected Success Rate: {simulation.estimated_success_rate:.2%}")
        logger.info(f"=" * 80)
        
        return {
            "success": True,
            "failure": failure,
            "analysis": analysis,
            "diagnosis": diagnosis,
            "simulation": simulation,
            "shadow_result": shadow_result,
            "patch": patch,
            "classified_patch": classified_patch,
            "patch_applied": patch_applied,
            "message": "Agent successfully patched" if patch_applied else "Patch created, awaiting manual approval"
        }
    
    def get_agent_status(self, agent_id: str) -> AgentState:
        """
        Get the current status of an agent.
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            AgentState object with current status
        """
        return self.patcher.get_agent_state(agent_id)
    
    def rollback_patch(self, patch_id: str) -> bool:
        """
        Rollback a previously applied patch.
        
        Args:
            patch_id: ID of the patch to rollback
            
        Returns:
            True if rollback was successful
        """
        return self.patcher.rollback_patch(patch_id)
    
    def get_failure_history(self, agent_id: Optional[str] = None, limit: int = 100) -> List[AgentFailure]:
        """
        Get failure history.
        
        Args:
            agent_id: Optional filter by agent ID
            limit: Maximum number of failures to return
            
        Returns:
            List of AgentFailure objects
        """
        return self.detector.get_failure_history(agent_id, limit)
    
    def get_patch_history(self, agent_id: Optional[str] = None) -> List[CorrectionPatch]:
        """
        Get patch history.
        
        Args:
            agent_id: Optional filter by agent ID
            
        Returns:
            List of CorrectionPatch objects
        """
        return self.patcher.get_patch_history(agent_id)
    
    def wake_up_and_fix(self, agent_id: str, error_message: str, context: Optional[Dict[str, Any]] = None):
        """
        Convenience method that wakes up the kernel, analyzes the failure,
        simulates a better path, and patches the agent.
        
        This is the main method referenced in the problem statement.
        
        Args:
            agent_id: ID of the failed agent
            error_message: Error message from the failure
            context: Additional context
        """
        logger.info("🚀 Kernel waking up to fix agent failure...")
        result = self.handle_failure(agent_id, error_message, context, auto_patch=True)
        
        if result["success"] and result["patch_applied"]:
            logger.info("✅ Agent fixed and patched successfully!")
        else:
            logger.warning("⚠️ Agent fix incomplete, manual intervention may be required")
        
        return result
    
    # ============================================================================
    # DUAL-LOOP ARCHITECTURE: Loop 2 (Alignment Engine) Methods
    # ============================================================================
    
    def handle_outcome(
        self,
        agent_id: str,
        user_prompt: str,
        agent_response: str,
        context: Optional[Dict[str, Any]] = None,
        tool_telemetry: Optional[List[ToolExecutionTelemetry]] = None,
        auto_nudge: bool = True
    ) -> Dict[str, Any]:
        """
        Handle an agent outcome through the Alignment Engine (Loop 2).
        
        This is the entry point for the Completeness Auditor. Instead of waiting
        for hard failures, we proactively detect when agents "give up" with
        negative results.
        
        Enhanced with:
        - Tool execution telemetry correlation
        - Automatic nudging on give-up detection
        - Semantic analysis
        
        Args:
            agent_id: ID of the agent
            user_prompt: Original user request
            agent_response: Agent's response
            context: Additional context
            tool_telemetry: Optional tool execution telemetry
            auto_nudge: Whether to automatically nudge on give-up (default: True)
            
        Returns:
            Dictionary with outcome analysis, audit results, and nudge results
        """
        logger.info(f"🔄 Loop 2 (Alignment Engine): Analyzing outcome for {agent_id}")
        
        # Step 1: Analyze the outcome with enhanced telemetry
        outcome = self.outcome_analyzer.analyze_outcome(
            agent_id=agent_id,
            user_prompt=user_prompt,
            agent_response=agent_response,
            context=context,
            tool_telemetry=tool_telemetry
        )
        
        result = {
            "outcome": outcome,
            "audit": None,
            "patch": None,
            "classified_patch": None,
            "nudge_result": None
        }
        
        # Step 2: Check if this triggers Completeness Audit (Give-Up Signal)
        if self.outcome_analyzer.should_trigger_audit(outcome):
            logger.info(f"🔍 Give-Up Signal detected! Triggering Completeness Auditor...")
            
            # Step 2a: Auto-nudge if enabled
            if auto_nudge and self.nudge_mechanism.should_nudge(outcome):
                logger.info(f"💡 Auto-nudge enabled - attempting nudge...")
                nudge_prompt = self.nudge_mechanism.generate_nudge(outcome)
                logger.info(f"Nudge prompt: {nudge_prompt[:100]}...")
                
                # Note: In a real system, you would re-invoke the agent with the nudge
                # For demo purposes, we'll simulate the nudge result
                # Real implementation would call: retry_response = agent.invoke(nudge_prompt)
                result["nudge_prompt"] = nudge_prompt
                logger.info(f"✓ Nudge prompt generated (agent should be re-invoked)")
            
            # Step 3: Run Completeness Audit (Differential Auditing)
            audit = self.completeness_auditor.audit_give_up(outcome)
            result["audit"] = audit
            
            # Step 4: If teacher found data (laziness detected), create competence patch
            if audit.teacher_found_data:
                logger.info(f"⚠️  LAZINESS DETECTED: Creating competence patch...")
                
                # Create a patch from the competence lesson
                patch = self._create_competence_patch(agent_id, audit)
                result["patch"] = patch
                
                # Step 5: Classify patch for lifecycle management (Semantic Purge)
                classified_patch = self.semantic_purge.register_patch(
                    patch=patch,
                    current_model_version=self.current_model_version
                )
                result["classified_patch"] = classified_patch
                
                # Register with auditor
                self.semantic_purge.register_completeness_audit(
                    audit=audit,
                    current_model_version=self.current_model_version
                )
                
                # Apply patch
                if self.config.get("auto_patch", True):
                    self.patcher.apply_patch(patch)
                    logger.info(f"✓ Competence patch applied")
        else:
            logger.info(f"✓ No give-up signal detected - agent performing well")
        
        return result
    
    def _create_competence_patch(
        self,
        agent_id: str,
        audit: CompletenessAudit
    ) -> CorrectionPatch:
        """
        Create a patch from a completeness audit.
        
        Competence patches teach the agent to avoid giving up too early.
        """
        import uuid
        from datetime import datetime
        from .models import FailureAnalysis, SimulationResult, AgentFailure, FailureType, FailureSeverity
        
        # Create a synthetic failure for the audit
        failure = AgentFailure(
            agent_id=agent_id,
            failure_type=FailureType.LOGIC_ERROR,
            severity=FailureSeverity.MEDIUM,
            error_message=f"Agent gave up: {audit.agent_outcome.agent_response}",
            context=audit.agent_outcome.context
        )
        
        # Create analysis
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Agent gave up too early without exhaustive search",
            contributing_factors=[audit.gap_analysis],
            suggested_fixes=[audit.competence_patch],
            confidence_score=audit.confidence,
            similar_failures=[]
        )
        
        # Create simulation
        simulation = SimulationResult(
            simulation_id=f"sim-{uuid.uuid4().hex[:8]}",
            success=True,
            alternative_path=[
                {
                    "step": 1,
                    "action": "exhaustive_search",
                    "description": "Check all data sources before reporting 'not found'"
                },
                {
                    "step": 2,
                    "action": "apply_competence_lesson",
                    "description": audit.competence_patch
                }
            ],
            expected_outcome="Agent will search exhaustively before giving up",
            risk_score=0.1,
            estimated_success_rate=0.9
        )
        
        # Create patch
        patch_id = f"competence-patch-{uuid.uuid4().hex[:8]}"
        
        patch = CorrectionPatch(
            patch_id=patch_id,
            agent_id=agent_id,
            failure_analysis=analysis,
            simulation_result=simulation,
            patch_type="system_prompt",
            patch_content={
                "type": "competence_rule",
                "rule": audit.competence_patch,
                "from_audit": audit.audit_id,
                "teacher_model": audit.teacher_model
            },
            applied=False
        )
        
        return patch
    
    def upgrade_model(self, new_model_version: str) -> Dict[str, Any]:
        """
        Upgrade the model version and trigger Semantic Purge.
        
        This is the "Purge Event" that removes Type A (Syntax) patches
        that are likely fixed in the new model version.
        
        Args:
            new_model_version: New model version (e.g., "gpt-5")
            
        Returns:
            Dictionary with purge statistics
        """
        logger.info(f"=" * 80)
        logger.info(f"MODEL UPGRADE: {self.current_model_version} → {new_model_version}")
        logger.info(f"=" * 80)
        
        old_version = self.current_model_version
        
        # Trigger semantic purge
        purge_result = self.semantic_purge.purge_on_upgrade(
            old_model_version=old_version,
            new_model_version=new_model_version
        )
        
        # Update model version
        self.current_model_version = new_model_version
        
        # Update all agent states
        for agent_state in self.patcher.agent_states.values():
            agent_state.model_version = new_model_version
        
        logger.info(f"=" * 80)
        logger.info(f"MODEL UPGRADE COMPLETE")
        logger.info(f"  Purged: {purge_result['stats']['purged_count']} Type A patches")
        logger.info(f"  Retained: {purge_result['stats']['retained_count']} Type B patches")
        logger.info(f"  Tokens Reclaimed: {purge_result['stats']['tokens_reclaimed']}")
        logger.info(f"=" * 80)
        
        return purge_result
    
    def get_alignment_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the Alignment Engine (Loop 2).
        
        Enhanced to include:
        - Completeness auditor metrics
        - Semantic purge metrics
        - Nudge mechanism effectiveness
        - Value delivery metrics (competence focus)
        
        Returns:
            Dictionary with comprehensive stats about quality and efficiency
        """
        return {
            "completeness_auditor": self.completeness_auditor.get_audit_stats(),
            "semantic_purge": self.semantic_purge.get_purge_stats(),
            "outcome_analyzer": {
                "total_outcomes": len(self.outcome_analyzer.outcome_history),
                "give_up_rate": self.outcome_analyzer.get_give_up_rate()
            },
            "nudge_mechanism": self.nudge_mechanism.get_nudge_stats(),
            "value_delivery": self._calculate_value_delivery_metrics()
        }
    
    def _calculate_value_delivery_metrics(self) -> Dict[str, Any]:
        """
        Calculate metrics focused on competence and value delivery.
        
        This differentiates the system from standard governance tools
        that only focus on safety/compliance (Loop 1). We measure:
        - Give-up rate (lower is better)
        - Laziness detection rate
        - Nudge success rate
        - Competence patch effectiveness
        
        Returns:
            Dictionary with value delivery metrics
        """
        audit_stats = self.completeness_auditor.get_audit_stats()
        nudge_stats = self.nudge_mechanism.get_nudge_stats()
        give_up_rate = self.outcome_analyzer.get_give_up_rate()
        
        # Calculate competence score (0-100)
        # Higher score = better value delivery
        competence_score = 100.0
        
        # Penalize for high give-up rate
        competence_score -= (give_up_rate * 30)  # Max 30 point penalty
        
        # Penalize for laziness detection
        laziness_rate = audit_stats.get("laziness_rate", 0.0)
        competence_score -= (laziness_rate * 40)  # Max 40 point penalty
        
        # Reward for nudge effectiveness
        nudge_success_rate = nudge_stats.get("success_rate", 0.0)
        competence_score += (nudge_success_rate * 20)  # Max 20 point bonus
        
        # Ensure bounds
        competence_score = max(0, min(100, competence_score))
        
        return {
            "competence_score": round(competence_score, 2),
            "give_up_rate": round(give_up_rate, 4),
            "laziness_detection_rate": round(laziness_rate, 4),
            "nudge_success_rate": round(nudge_success_rate, 4),
            "total_audits": audit_stats.get("total_audits", 0),
            "laziness_caught": audit_stats.get("laziness_detected", 0),
            "focus": "Competence & Value Delivery (differentiates from safety-only tools)"
        }
    
    def get_classified_patches(self) -> Dict[str, List[ClassifiedPatch]]:
        """
        Get patches classified by type.
        
        Returns:
            Dictionary with purgeable and permanent patches
        """
        return {
            "purgeable": self.semantic_purge.get_purgeable_patches(),
            "permanent": self.semantic_purge.get_permanent_patches()
        }
    
    def process_async_queue(self, batch_size: int = 10) -> Dict[str, Any]:
        """
        Process failures from the async queue (background/nightly processing).
        
        This method would typically run in a background worker or during
        off-peak hours to fix non-critical failures that were queued.
        
        Args:
            batch_size: Maximum number of failures to process in this batch
            
        Returns:
            Dictionary with processing statistics
        """
        logger.info(f"=" * 80)
        logger.info(f"ASYNC QUEUE PROCESSING - Processing up to {batch_size} failures")
        logger.info(f"Queue size: {len(self.async_failure_queue)}")
        logger.info(f"=" * 80)
        
        processed = 0
        succeeded = 0
        failed = 0
        
        # Process up to batch_size items
        while self.async_failure_queue and processed < batch_size:
            failure_data = self.async_failure_queue.pop(0)
            processed += 1
            
            logger.info(f"Processing async failure {processed}/{batch_size}")
            logger.info(f"  Agent: {failure_data['agent_id']}")
            logger.info(f"  Error: {failure_data['error_message']}")
            
            try:
                # Process the failure without triage (already decided async)
                # Temporarily remove user_prompt to skip triage
                user_prompt = failure_data.pop('user_prompt', None)
                
                result = self.handle_failure(
                    agent_id=failure_data['agent_id'],
                    error_message=failure_data['error_message'],
                    context=failure_data.get('context'),
                    stack_trace=failure_data.get('stack_trace'),
                    auto_patch=True,
                    user_prompt=None,  # Skip triage by not providing user_prompt
                    chain_of_thought=failure_data.get('chain_of_thought'),
                    failed_action=failure_data.get('failed_action')
                )
                
                if result.get('success') and result.get('patch_applied'):
                    succeeded += 1
                    logger.info(f"  ✓ Fixed successfully")
                else:
                    failed += 1
                    logger.info(f"  ✗ Fix failed")
            except Exception as e:
                failed += 1
                logger.error(f"  ✗ Error processing: {str(e)}")
        
        logger.info(f"=" * 80)
        logger.info(f"ASYNC QUEUE PROCESSING COMPLETE")
        logger.info(f"  Processed: {processed}")
        logger.info(f"  Succeeded: {succeeded}")
        logger.info(f"  Failed: {failed}")
        logger.info(f"  Remaining in queue: {len(self.async_failure_queue)}")
        logger.info(f"=" * 80)
        
        return {
            "processed": processed,
            "succeeded": succeeded,
            "failed": failed,
            "remaining": len(self.async_failure_queue)
        }
    
    def get_triage_stats(self) -> Dict[str, Any]:
        """
        Get statistics about triage decisions.
        
        Returns:
            Dictionary with triage statistics
        """
        return {
            "async_queue_size": len(self.async_failure_queue),
            "critical_tools": len(self.triage.critical_tools),
            "high_effort_keywords": len(self.triage.high_effort_keywords)
        }
