# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for explicit external-target metadata configuration helpers."""

from __future__ import annotations

import json
from pathlib import Path

from .target import load_metadata_document


def test_metadata_document_is_machine_readable(tmp_path: Path):
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(
        json.dumps(
            {
                "operations": [
                    {
                        "method": "GET",
                        "path": "/api/v1/health",
                        "operationId": "getHealth",
                        "x-capability-flags": {
                            "runtime_mutating": False,
                            "user_intent_required": False,
                            "read_only_surface": True,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    document = load_metadata_document(metadata_path)
    assert document["operations"][0]["operationId"] == "getHealth"
