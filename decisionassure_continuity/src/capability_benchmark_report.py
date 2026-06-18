import json
from datetime import datetime

def generate_benchmark_report(results: dict, output_file: str = "benchmark_report.json"):
    report = {
        "benchmark_version": "v1",
        "timestamp": datetime.now().isoformat(),
        "train_size": results["train_size"],
        "test_size": results["test_size"],
        "metrics": {
            "precision": results["precision"],
            "recall": results["recall"],
            "f1_score": results["f1_score"],
            "discovery_rate": results["discovery_rate"],
            "false_discovery_rate": results["false_discovery_rate"],
            "cluster_purity": results["cluster_purity"],
            "analyst_mapping_accuracy": results["analyst_mapping_accuracy"],
        },
        "known_capabilities": [
            {"name": cap["capability_name"], "severity": cap["severity"]}
            for cap in results["known_clusters"]
        ],
        "emergent_clusters": [
            {
                "id": f"cluster_{i}",
                "actions": cap["required_actions"],
                "occurrences": cap["occurrence_count"],
                "witness_hash": cap["witness"]["witness_hash"],
                "severity": cap["severity"],
            }
            for i, cap in enumerate(results["unknown_clusters"], 1)
        ],
        "hidden_capabilities": results["hidden_capabilities"],
        "summary": {
            "total_emergent_clusters": len(results["unknown_clusters"]),
            "hidden_mapped": results["discovery_rate"] * len(results["hidden_capabilities"]),
        }
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"✅ Benchmark report saved to {output_file}")