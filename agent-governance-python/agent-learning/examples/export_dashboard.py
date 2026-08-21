# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Export a governed Agent Learning dashboard snapshot as JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_learning import LocalFileStore

from agent_learning_gov import JsonlAuditSink, LearningGovernanceDashboardModel


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--task-id", default="default")
    parser.add_argument("--audit-file")
    parser.add_argument("--output", default="learning-governance-dashboard.json")
    args = parser.parse_args()

    audit = JsonlAuditSink(args.audit_file) if args.audit_file else None
    model = LearningGovernanceDashboardModel(
        LocalFileStore(args.data_dir),
        audit_sink=audit,
    )
    snapshot = model.snapshot(args.agent_id, task_id=args.task_id, limit=1000)
    output = Path(args.output)
    output.write_text(
        json.dumps(snapshot.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(output.resolve())


if __name__ == "__main__":
    main()
