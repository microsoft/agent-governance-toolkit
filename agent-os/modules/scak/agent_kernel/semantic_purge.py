# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Semantic Purge - Scale by Subtraction for patch lifecycle management.

Implements the "Taxonomy of Lessons" to prevent context bloat:
- Type A (Syntax/Capability): High decay - likely model defects, purge on upgrade
- Type B (Business/Context): Zero decay - world truths, retain forever

This allows reducing context usage by 40-60% over the agent's lifetime.
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime

from .models import (
    CorrectionPatch, ClassifiedPatch, PatchDecayType, 
    CognitiveGlitch, CompletenessAudit
)

logger = logging.getLogger(__name__)


class PatchClassifier:
    """
    Classifies patches into Type A (Syntax) vs Type B (Business).
    
    This is the "Taxonomy of Lessons" that determines lifecycle.
    """
    
    def __init__(self):
        self.syntax_indicators = [
            "output json", "format", "syntax", "parse", "validation error",
            "type mismatch", "parameter type", "limit 10", "use uuid",
            "tool definition", "schema injection", "parameter checking"
        ]
        
        self.business_indicators = [
            "fiscal year", "project", "entity", "business rule", "policy",
            "archived", "deprecated", "does not exist", "negative constraint",
            "company", "organization", "domain", "customer", "workflow"
        ]
    
    def classify_patch(
        self,
        patch: CorrectionPatch,
        current_model_version: str
    ) -> ClassifiedPatch:
        """
        Classify a patch as Type A or Type B.
        
        Args:
            patch: The correction patch to classify
            current_model_version: Current model version (e.g., "gpt-4o", "gpt-5")
            
        Returns:
            ClassifiedPatch with decay type and metadata
        """
        logger.info(f"Classifying patch {patch.patch_id}")
        
        # Analyze patch content to determine type
        decay_type = self._determine_decay_type(patch)
        
        # Determine if should purge on upgrade
        should_purge = (decay_type == PatchDecayType.SYNTAX_CAPABILITY)
        
        # Build metadata
        metadata = self._build_decay_metadata(patch, decay_type)
        
        classified = ClassifiedPatch(
            base_patch=patch,
            decay_type=decay_type,
            created_at_model_version=current_model_version,
            decay_metadata=metadata,
            should_purge_on_upgrade=should_purge
        )
        
        logger.info(f"Classified as {decay_type.value} (purge on upgrade: {should_purge})")
        
        return classified
    
    def _determine_decay_type(self, patch: CorrectionPatch) -> PatchDecayType:
        """
        Determine if patch is Type A (Syntax) or Type B (Business).
        
        Type A - Syntax/Capability (HIGH DECAY):
        - Model-specific issues (JSON formatting, type errors)
        - Tool usage errors (wrong parameter types)
        - Syntax errors, validation issues
        - Query construction problems
        - These are likely fixed in newer model versions
        
        Type B - Business/Context (ZERO DECAY):
        - Company-specific rules ("Fiscal year starts in July")
        - Entity existence ("Project_Alpha is deprecated")
        - Policy violations (medical advice restrictions)
        - Domain knowledge (archived locations, workflows)
        - These are world truths that models can't learn
        """
        # Check diagnosis first (most reliable indicator)
        if patch.diagnosis:
            glitch = patch.diagnosis.cognitive_glitch
            
            # Tool misuse is almost always Type A (model capability issue)
            if glitch == CognitiveGlitch.TOOL_MISUSE:
                return PatchDecayType.SYNTAX_CAPABILITY
            
            # Policy violations are Type B (business rules)
            if glitch == CognitiveGlitch.POLICY_VIOLATION:
                return PatchDecayType.BUSINESS_CONTEXT
            
            # Hallucinations about entities are Type B (world knowledge)
            if glitch == CognitiveGlitch.HALLUCINATION:
                return PatchDecayType.BUSINESS_CONTEXT
            
            # Schema mismatches depend on content
            if glitch == CognitiveGlitch.SCHEMA_MISMATCH:
                # Check if it's about company-specific schema
                content_str = str(patch.patch_content).lower()
                if any(indicator in content_str for indicator in self.business_indicators):
                    return PatchDecayType.BUSINESS_CONTEXT
                return PatchDecayType.SYNTAX_CAPABILITY
        
        # Analyze patch content
        content_str = str(patch.patch_content).lower()
        
        # Count indicators
        syntax_score = sum(1 for ind in self.syntax_indicators if ind in content_str)
        business_score = sum(1 for ind in self.business_indicators if ind in content_str)
        
        # Check for specific patterns
        if patch.patch_type == "system_prompt":
            rule = patch.patch_content.get("rule", "")
            rule_lower = rule.lower()
            
            # Schema injection and parameter checking are Type A
            if "schema injection" in rule_lower or "parameter type" in rule_lower:
                return PatchDecayType.SYNTAX_CAPABILITY
            
            # Constitutional rules about domains are Type B
            if "constitutional" in rule_lower or "refuse" in rule_lower:
                return PatchDecayType.BUSINESS_CONTEXT
            
            # Entity-specific negative constraints are Type B
            if "does not exist" in rule_lower or "deprecated" in rule_lower:
                return PatchDecayType.BUSINESS_CONTEXT
        
        # RAG memory patches are typically Type B (business context)
        if patch.patch_type == "rag_memory":
            negative_constraint = patch.patch_content.get("negative_constraint")
            if negative_constraint:
                return PatchDecayType.BUSINESS_CONTEXT
        
        # Score-based classification
        if business_score > syntax_score:
            return PatchDecayType.BUSINESS_CONTEXT
        elif syntax_score > 0:
            return PatchDecayType.SYNTAX_CAPABILITY
        
        # Default to business context (safer - won't accidentally purge important rules)
        return PatchDecayType.BUSINESS_CONTEXT
    
    def _build_decay_metadata(self, patch: CorrectionPatch, decay_type: PatchDecayType) -> Dict:
        """Build metadata for decay management."""
        metadata = {
            "classification_reason": self._get_classification_reason(patch, decay_type),
            "estimated_lifetime": "until_upgrade" if decay_type == PatchDecayType.SYNTAX_CAPABILITY else "permanent",
            "priority": "low" if decay_type == PatchDecayType.SYNTAX_CAPABILITY else "high"
        }
        
        if decay_type == PatchDecayType.SYNTAX_CAPABILITY:
            metadata["purge_trigger"] = "model_version_upgrade"
            metadata["expected_fix_in"] = "next_model_generation"
        else:
            metadata["purge_trigger"] = "manual_review_only"
            metadata["rag_storage_recommended"] = True
        
        return metadata
    
    def _get_classification_reason(self, patch: CorrectionPatch, decay_type: PatchDecayType) -> str:
        """Get human-readable reason for classification."""
        if patch.diagnosis:
            glitch = patch.diagnosis.cognitive_glitch.value
            if decay_type == PatchDecayType.SYNTAX_CAPABILITY:
                return f"Model capability issue ({glitch}) - likely fixed in upgraded models"
            else:
                return f"Domain/business knowledge ({glitch}) - requires permanent retention"
        return "Content-based classification"


class SemanticPurge:
    """
    Manages patch lifecycle and purging.
    
    This is "Scale by Subtraction" - reducing context by purging temporary wisdom.
    """
    
    def __init__(self):
        self.classifier = PatchClassifier()
        self.classified_patches: Dict[str, ClassifiedPatch] = {}
        self.purge_history: List[Dict] = []
    
    def register_patch(
        self,
        patch: CorrectionPatch,
        current_model_version: str
    ) -> ClassifiedPatch:
        """
        Register a patch with classification for lifecycle management.
        
        Args:
            patch: The correction patch
            current_model_version: Current model version
            
        Returns:
            ClassifiedPatch with metadata
        """
        classified = self.classifier.classify_patch(patch, current_model_version)
        self.classified_patches[patch.patch_id] = classified
        
        logger.info(f"Registered patch {patch.patch_id} as {classified.decay_type.value}")
        
        return classified
    
    def purge_on_upgrade(
        self,
        old_model_version: str,
        new_model_version: str
    ) -> Dict[str, List[str]]:
        """
        Purge Type A patches when model version upgrades.
        
        This is the "Purge Event" - async purging to reclaim tokens.
        
        Args:
            old_model_version: Previous model version
            new_model_version: New model version
            
        Returns:
            Dictionary with purged and retained patch IDs
        """
        logger.info(f"🗑️  PURGE EVENT: Model upgrade {old_model_version} → {new_model_version}")
        
        purged_patches = []
        retained_patches = []
        
        for patch_id, classified in self.classified_patches.items():
            if classified.should_purge_on_upgrade:
                # This is Type A (Syntax) - likely fixed in new model
                purged_patches.append(patch_id)
                logger.info(f"   Purging Type A patch {patch_id}: {classified.decay_metadata.get('classification_reason', '')}")
            else:
                # This is Type B (Business) - retain forever
                retained_patches.append(patch_id)
        
        # Record purge event
        purge_event = {
            "timestamp": datetime.utcnow(),
            "old_version": old_model_version,
            "new_version": new_model_version,
            "purged_count": len(purged_patches),
            "retained_count": len(retained_patches),
            "purged_patches": purged_patches,
            "tokens_reclaimed": self._estimate_tokens_reclaimed(purged_patches)
        }
        
        self.purge_history.append(purge_event)
        
        # Remove purged patches
        for patch_id in purged_patches:
            del self.classified_patches[patch_id]
        
        logger.info(f"✓ Purged {len(purged_patches)} Type A patches")
        logger.info(f"✓ Retained {len(retained_patches)} Type B patches")
        logger.info(f"✓ Estimated tokens reclaimed: {purge_event['tokens_reclaimed']}")
        
        return {
            "purged": purged_patches,
            "retained": retained_patches,
            "stats": {
                "purged_count": len(purged_patches),
                "retained_count": len(retained_patches),
                "tokens_reclaimed": purge_event["tokens_reclaimed"]
            }
        }
    
    def _estimate_tokens_reclaimed(self, purged_patch_ids: List[str]) -> int:
        """
        Estimate tokens reclaimed by purging patches.
        
        Rough estimate: each patch uses 50-200 tokens depending on complexity.
        """
        return len(purged_patch_ids) * 100  # Average 100 tokens per patch
    
    def get_purge_stats(self) -> Dict:
        """Get statistics about purging activity."""
        total_patches = len(self.classified_patches)
        type_a_count = sum(1 for p in self.classified_patches.values() 
                          if p.decay_type == PatchDecayType.SYNTAX_CAPABILITY)
        type_b_count = sum(1 for p in self.classified_patches.values()
                          if p.decay_type == PatchDecayType.BUSINESS_CONTEXT)
        
        total_purged = sum(event["purged_count"] for event in self.purge_history)
        total_tokens_reclaimed = sum(event["tokens_reclaimed"] for event in self.purge_history)
        
        return {
            "current_patches": total_patches,
            "type_a_syntax": type_a_count,
            "type_b_business": type_b_count,
            "purge_events": len(self.purge_history),
            "total_purged": total_purged,
            "total_tokens_reclaimed": total_tokens_reclaimed,
            "estimated_savings": f"{(type_a_count / (total_patches or 1)) * 100:.1f}% can be purged on upgrade"
        }
    
    def get_purgeable_patches(self) -> List[ClassifiedPatch]:
        """Get list of patches that would be purged on upgrade."""
        return [
            p for p in self.classified_patches.values()
            if p.should_purge_on_upgrade
        ]
    
    def get_permanent_patches(self) -> List[ClassifiedPatch]:
        """Get list of permanent (Type B) patches."""
        return [
            p for p in self.classified_patches.values()
            if not p.should_purge_on_upgrade
        ]
    
    def register_completeness_audit(
        self,
        audit: CompletenessAudit,
        current_model_version: str
    ):
        """
        Register a competence patch from completeness audit.
        
        Competence patches are always Type B (business context) because they
        represent gaps in domain knowledge, not model defects.
        """
        # Create a synthetic patch for the competence lesson
        # In a real system, this would be integrated with the patcher
        logger.info(f"Registering competence patch from audit {audit.audit_id}")
        logger.info(f"   Lesson: {audit.competence_patch[:80]}...")
        
        # Competence patches are always Type B - domain knowledge
        # These represent what the agent didn't know about the domain/business
