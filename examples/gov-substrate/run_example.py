"""Minimal real allow/deny/grant/shutdown demonstration using only local services."""

import argparse
import json

from run_proof import HERE, Deployment, command, denied, email, prove_unavailable


def run(gov_source):
    deployment = Deployment(gov_source)
    try:
        deployment.start()
        allowed = deployment.worker(deployment.tool("send_email", email("allowed")))[
            "body"
        ]
        assert allowed["outcome"] == "succeeded"
        assert len(deployment.read_effects("smtp.jsonl")) == 1
        deployment.note("both_permit_execution", allowed)
        for tool, system in (("blocked_email", "agt"), ("restricted_email", "gov-sub")):
            result = denied(
                deployment.worker(deployment.tool(tool, email("denied"))), system
            )
            assert len(deployment.read_effects("smtp.jsonl")) == 1
            deployment.note(system + "_denial_no_effect", result)
        args = email("one-use")
        grant = deployment.rpc("POST", "/prepare", deployment.tool("send_email", args))
        request = {"handle": grant["handle"], "args": args}
        assert deployment.rpc("POST", "/dispatch", request)["outcome"] == "succeeded"
        assert (
            denied(deployment.rpc("POST", "/dispatch", request))["reason"]
            == "execution_grant_reused"
        )
        assert len(deployment.read_effects("smtp.jsonl")) == 2
        deployment.note("one_use_grant", {"deliveries": 2})
        prove_unavailable(deployment)
        shutdown = deployment.rpc("POST", "/shutdown", {})
        assert shutdown["terminated"] is True
        assert shutdown["receipt"]["workers"][0]["runtime_id"] == deployment.worker_id
        assert (
            command("docker", "inspect", deployment.worker_id, check=False).returncode
            != 0
        )
        deployment.note("verified_worker_shutdown", shutdown)
        events = deployment.collect()
        result = {
            "result": "PASS",
            "cases": deployment.records,
            "agt_audit": deployment.agt_audit,
            "substrate_events": events,
            "smtp_receipts": deployment.read_effects("smtp.jsonl"),
        }
        serialized = json.dumps(result, indent=2, default=str)
        assert not any(token in serialized for token in deployment.tokens.values())
        destination = HERE / ".local" / "example-proof.json"
        destination.write_text(serialized + "\n", encoding="utf-8", newline="\n")
        print("Evidence: " + str(destination))
        return result
    finally:
        deployment.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gov-source", required=True)
    run(parser.parse_args().gov_source)
