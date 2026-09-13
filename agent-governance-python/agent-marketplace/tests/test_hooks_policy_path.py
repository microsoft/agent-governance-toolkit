# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression test for native manifest path validation."""
from __future__ import annotations
import sys
from agent_marketplace import hooks
_MANIFEST_TEMPLATE = 'name: example-plugin\nversion: 1.0.0\nauthor: test-author\ndescription: Example\nplugin_type: integration\n'

def test_missing_manifest_path_exits_nonzero(monkeypatch, tmp_path, capsys):
    manifest = tmp_path / 'agent-plugin.yaml'
    manifest.write_text(_MANIFEST_TEMPLATE, encoding='utf-8')
    monkeypatch.setattr(
        sys,
        'argv',
        [
            'evaluate-governance',
            '--manifest',
            str(tmp_path / 'does-not-exist.yaml'),
            str(manifest),
        ],
    )
    rc = hooks.evaluate_governance_cli()
    captured = capsys.readouterr()
    assert rc == 1
    assert 'Unable to load native governance runtime' in captured.err
