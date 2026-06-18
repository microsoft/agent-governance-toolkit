"""
Governance Coverage Curve & Governance Knowledge Accumulation Index (GKAI)
Tracks how governance coverage increases with ontology evolution.
"""

from typing import List, Dict, Any
import json
import os
from datetime import datetime
from src.capability_discovery import CapabilityDiscovery
from src.capability_ontology import load_ontology_from_file, OntologyMatcher, load_combined_ontology, TRAINING_ONTOLOGY

class GovernanceCoverageTracker:
    def __init__(self, traces: List[List[Any]]):
        self.traces = traces
        self.history: List[Dict[str, Any]] = []
        self._load_history()

    def _load_history(self):
        if os.path.exists("coverage_history.json"):
            with open("coverage_history.json", 'r') as f:
                self.history = json.load(f)

    def _save_history(self):
        with open("coverage_history.json", 'w') as f:
            json.dump(self.history, f, indent=2)

    def compute_coverage(self, ontology_path: str = "evolved_ontology.json", use_combined: bool = False) -> Dict[str, Any]:
        """
        Compute coverage metrics.
        - Classification Rate: classified / total discovered
        - Ontology Coverage: classified / (known + classified)
        """
        if use_combined:
            from src.capability_ontology import load_combined_ontology, TRAINING_ONTOLOGY
            ont = load_combined_ontology(TRAINING_ONTOLOGY, ontology_path)
        else:
            ont = load_ontology_from_file(ontology_path)
            if not ont.patterns:
                ont = TRAINING_ONTOLOGY

        discovery = CapabilityDiscovery(min_samples=2, eps=0.5)
        discovery.ontology_matcher = OntologyMatcher(ontology=ont)
        discovered = discovery.discover(self.traces)

        classified = len([cap for cap in discovered if cap['classification'] != 'unknown'])
        total = len(discovered)
        unknown = total - classified

        from src.capability_ontology import KNOWN_PATTERNS
        known_total = len(KNOWN_PATTERNS)
        total_possible = known_total + classified

        # TWO METRICS:
        # 1. Classification Rate: what % of discovered capabilities are classified
        classification_rate = classified / total if total > 0 else 0.0
        # 2. Ontology Coverage: what % of all possible capabilities are known
        ontology_coverage = classified / total_possible if total_possible > 0 else 0.0

        approved_names = []
        ledger_file = "data/ontology_ledger.json"
        if os.path.exists(ledger_file):
            with open(ledger_file, 'r') as f:
                ledger = json.load(f)
                for entry in ledger:
                    if entry.get('action') == 'add':
                        approved_names.append(entry.get('capability_name', 'Unknown'))

        return {
            "version": len(self.history) + 1,
            "classified": classified,
            "unknown": unknown,
            "total": total,
            "known_total": known_total,
            "classification_rate_percent": round(classification_rate * 100, 1),
            "ontology_coverage_percent": round(ontology_coverage * 100, 1),
            "approved_capabilities": approved_names,
            "timestamp": datetime.now().isoformat()
        }

    def record_snapshot(self, ontology_path: str = "evolved_ontology.json", use_combined: bool = False) -> Dict[str, Any]:
        snapshot = self.compute_coverage(ontology_path, use_combined=use_combined)
        if not self.history or self.history[-1].get('version') != snapshot['version']:
            self.history.append(snapshot)
            self._save_history()
        return snapshot

    def get_curve(self) -> List[Dict[str, Any]]:
        return self.history

    def compute_gkai(self) -> Dict[str, Any]:
        """Compute Governance Knowledge Accumulation Index."""
        if len(self.history) < 2:
            return {
                "total_versions": len(self.history),
                "total_gain": 0.0,
                "average_gain": 0.0,
                "history": self.history
            }

        base_coverage = self.history[0].get('ontology_coverage_percent', 0.0)
        latest_coverage = self.history[-1].get('ontology_coverage_percent', 0.0)
        total_gain = latest_coverage - base_coverage
        average_gain = total_gain / (len(self.history) - 1) if len(self.history) > 1 else 0.0

        return {
            "total_versions": len(self.history),
            "base_coverage": base_coverage,
            "latest_coverage": latest_coverage,
            "total_gain": round(total_gain, 1),
            "average_gain": round(average_gain, 1),
            "history": self.history
        }

    def display_curve(self):
        if not self.history:
            print("No coverage history available.")
            return

        print("\n📈 Governance Coverage Curve")
        print("=" * 65)
        print("  Version   Classification Rate   Ontology Coverage   Capabilities")
        print("  " + "-" * 60)
        for entry in self.history:
            caps = ", ".join(entry.get('approved_capabilities', []))
            if not caps:
                caps = "(base ontology)"
            print(f"  v{entry['version']:<7}  {entry['classification_rate_percent']:>5}%                  {entry['ontology_coverage_percent']:>5}%        {caps}")
        print("=" * 65)

    def display_gkai(self):
        """Display the Governance Knowledge Accumulation Index."""
        gkai = self.compute_gkai()
        print("\n📊 Governance Knowledge Accumulation Index (GKAI)")
        print("=" * 55)
        print(f"   Total versions tracked:    {gkai['total_versions']}")
        print(f"   Base ontology coverage:    {gkai['base_coverage']:.1f}%")
        print(f"   Latest coverage:           {gkai['latest_coverage']:.1f}%")
        print(f"   Total knowledge gain:      +{gkai['total_gain']:.1f}%")
        print(f"   Average gain per version:  +{gkai['average_gain']:.1f}%")
        print("=" * 55)