#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration test script to verify IATP v0.2.0 functionality
"""

import sys
import subprocess
import time
import httpx
import asyncio
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


class TestRunner:
    def __init__(self):
        self.processes = []
        self.passed = 0
        self.failed = 0
    
    def log(self, msg, level="INFO"):
        prefix = {
            "INFO": "ℹ️ ",
            "SUCCESS": "✅",
            "ERROR": "❌",
            "WARN": "⚠️ "
        }.get(level, "  ")
        print(f"{prefix} {msg}")
    
    def test_imports(self):
        """Test that all modules import correctly"""
        self.log("Testing imports...", "INFO")
        try:
            from iatp.models import (
                CapabilityManifest,
                TrustLevel,
                AgentCapabilities,
                ReversibilityLevel,
                PrivacyContract,
                RetentionPolicy
            )
            from iatp.sidecar import create_sidecar
            from iatp.security import SecurityValidator
            from iatp.telemetry import FlightRecorder
            
            self.log("All imports successful", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Import failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_manifest_creation(self):
        """Test creating a capability manifest"""
        self.log("Testing manifest creation...", "INFO")
        try:
            from iatp.models import (
                CapabilityManifest,
                TrustLevel,
                AgentCapabilities,
                ReversibilityLevel,
                PrivacyContract,
                RetentionPolicy
            )
            
            manifest = CapabilityManifest(
                agent_id="test-agent",
                trust_level=TrustLevel.TRUSTED,
                capabilities=AgentCapabilities(
                    reversibility=ReversibilityLevel.FULL,
                    idempotency=True,
                    sla_latency="2000ms",
                    rate_limit=100
                ),
                privacy_contract=PrivacyContract(
                    retention=RetentionPolicy.EPHEMERAL,
                    human_review=False
                )
            )
            
            assert manifest.agent_id == "test-agent"
            assert manifest.trust_level == TrustLevel.TRUSTED
            
            self.log("Manifest creation successful", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Manifest creation failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_trust_score(self):
        """Test trust score calculation"""
        self.log("Testing trust score calculation...", "INFO")
        try:
            from iatp.models import (
                CapabilityManifest,
                TrustLevel,
                AgentCapabilities,
                ReversibilityLevel,
                PrivacyContract,
                RetentionPolicy
            )
            
            # High trust agent
            high_trust = CapabilityManifest(
                agent_id="high-trust",
                trust_level=TrustLevel.VERIFIED_PARTNER,
                capabilities=AgentCapabilities(
                    reversibility=ReversibilityLevel.FULL,
                    idempotency=True
                ),
                privacy_contract=PrivacyContract(
                    retention=RetentionPolicy.EPHEMERAL,
                    human_review=False
                )
            )
            
            score = high_trust.calculate_trust_score()
            assert score >= 10, f"Expected score >= 10, got {score}"
            
            # Low trust agent
            low_trust = CapabilityManifest(
                agent_id="low-trust",
                trust_level=TrustLevel.UNTRUSTED,
                capabilities=AgentCapabilities(
                    reversibility=ReversibilityLevel.NONE,
                    idempotency=False
                ),
                privacy_contract=PrivacyContract(
                    retention=RetentionPolicy.PERMANENT,
                    human_review=True
                )
            )
            
            score = low_trust.calculate_trust_score()
            assert score <= 2, f"Expected score <= 2, got {score}"
            
            self.log(f"Trust score calculation correct (high: {high_trust.calculate_trust_score()}, low: {low_trust.calculate_trust_score()})", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Trust score calculation failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_sensitive_data_detection(self):
        """Test sensitive data detection"""
        self.log("Testing sensitive data detection...", "INFO")
        try:
            from iatp.security import SecurityValidator
            
            validator = SecurityValidator()
            
            # Test credit card detection
            cc_data = {"payment": "4532-0151-1283-0366"}
            result = validator.detect_sensitive_data(cc_data)
            assert "credit_card" in result, "Credit card not detected"
            
            # Test SSN detection
            ssn_data = {"ssn": "123-45-6789"}
            result = validator.detect_sensitive_data(ssn_data)
            assert "ssn" in result, "SSN not detected"
            
            # Test clean data
            clean_data = {"message": "Hello world"}
            result = validator.detect_sensitive_data(clean_data)
            assert "credit_card" not in result and "ssn" not in result, "False positive detected"
            
            self.log("Sensitive data detection working correctly", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Sensitive data detection failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_go_sidecar_files(self):
        """Test that Go sidecar files exist"""
        self.log("Testing Go sidecar files...", "INFO")
        try:
            go_files = [
                project_root / "sidecar" / "go" / "main.go",
                project_root / "sidecar" / "go" / "go.mod",
                project_root / "sidecar" / "go" / "Dockerfile",
                project_root / "sidecar" / "go" / "README.md",
            ]
            
            for file in go_files:
                assert file.exists(), f"Missing: {file}"
            
            self.log("All Go sidecar files present", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Go sidecar files check failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_experiment_files(self):
        """Test that experiment files exist"""
        self.log("Testing experiment files...", "INFO")
        try:
            exp_files = [
                project_root / "experiments" / "cascading_hallucination" / "agent_a_user.py",
                project_root / "experiments" / "cascading_hallucination" / "agent_b_summarizer.py",
                project_root / "experiments" / "cascading_hallucination" / "agent_c_database.py",
                project_root / "experiments" / "cascading_hallucination" / "sidecar_c.py",
                project_root / "experiments" / "cascading_hallucination" / "run_experiment.py",
                project_root / "experiments" / "cascading_hallucination" / "README.md",
            ]
            
            for file in exp_files:
                assert file.exists(), f"Missing: {file}"
            
            self.log("All experiment files present", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Experiment files check failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_docker_files(self):
        """Test that Docker files exist"""
        self.log("Testing Docker files...", "INFO")
        try:
            docker_files = [
                project_root / "docker-compose.yml",
                project_root / "docker" / "Dockerfile.agent",
                project_root / "docker" / "Dockerfile.sidecar-python",
                project_root / "docker" / "README.md",
            ]
            
            for file in docker_files:
                assert file.exists(), f"Missing: {file}"
            
            self.log("All Docker files present", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Docker files check failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def test_distribution_files(self):
        """Test that distribution files exist"""
        self.log("Testing distribution files...", "INFO")
        try:
            dist_files = [
                project_root / "setup.py",
                project_root / "MANIFEST.in",
                project_root / "CHANGELOG.md",
                project_root / "BLOG.md",
                project_root / "RFC_SUBMISSION.md",
            ]
            
            for file in dist_files:
                assert file.exists(), f"Missing: {file}"
            
            # Check setup.py version
            with open(project_root / "setup.py") as f:
                content = f.read()
                assert "0.2.0" in content, "Version not updated in setup.py"
            
            self.log("All distribution files present", "SUCCESS")
            self.passed += 1
            return True
        except Exception as e:
            self.log(f"Distribution files check failed: {e}", "ERROR")
            self.failed += 1
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "="*60)
        print("IATP v0.2.0 Integration Tests")
        print("="*60 + "\n")
        
        # Run tests
        self.test_imports()
        self.test_manifest_creation()
        self.test_trust_score()
        self.test_sensitive_data_detection()
        self.test_go_sidecar_files()
        self.test_experiment_files()
        self.test_docker_files()
        self.test_distribution_files()
        
        # Summary
        print("\n" + "="*60)
        print(f"Test Results: {self.passed} passed, {self.failed} failed")
        print("="*60 + "\n")
        
        if self.failed == 0:
            print("✅ All tests passed! IATP v0.2.0 is ready.")
            return 0
        else:
            print(f"❌ {self.failed} test(s) failed. Please review.")
            return 1


if __name__ == "__main__":
    runner = TestRunner()
    exit_code = runner.run_all_tests()
    sys.exit(exit_code)
