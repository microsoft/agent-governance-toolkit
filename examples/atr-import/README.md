# `atr-import` — community example

Compile Agent Threat Rules (ATR) YAML into per-category Agent OS
`PolicyDocument` YAML files.

This example is a **community integration**. It is not part of agent-os core
and does not register a CLI subcommand on `agentos`. AGT core takes no runtime
dependency on ATR; the integration lives here so it can evolve independently.

## What ATR is

[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
is an MIT-licensed open detection-rule library for AI agent and LLM threats.
v2.2.1, 419 rules across 10 categories.

## Relationship to PR #908

PR #908 added the cross-reference layer under `examples/atr-community-rules/`
with a `sync_atr_rules.py` helper. That helper emits a single bundled
`PolicyDocument` with all rules merged.

This example reuses #908's conversion logic and adds a per-category emit, so
each ATR category becomes one `PolicyDocument` that slots into AGT's
folder-merge policy layout. ATR-to-AGT rule mapping stays single-sourced in
`examples/atr-community-rules/sync_atr_rules.py`.

## Usage

```bash
# Compile ATR YAML into per-category Agent OS policies
python examples/atr-import/import_atr.py path/to/atr/rules/

# Pin the output directory and emit a JSON build manifest for CI pipelines
python examples/atr-import/import_atr.py rules/ \
    --out policies/ \
    --manifest build/atr-manifest.json

# Filter at compile time
python examples/atr-import/import_atr.py rules/ \
    --category prompt-injection \
    --min-severity high
python examples/atr-import/import_atr.py rules/ --id-prefix ATR-2026-

# Watch the ATR source tree and recompile on changes (stdlib mtime polling)
python examples/atr-import/import_atr.py rules/ --watch --watch-interval 2.0
```

## Locating PR #908's `sync_atr_rules.py`

`import_atr.py` walks up the parent chain from itself to find
`examples/atr-community-rules/sync_atr_rules.py` so the lookup is robust to
source-layout changes.

If you have moved that script (for example, in an installed deployment), set
the `AGT_ATR_SYNC_PATH` environment variable to its absolute path:

```bash
export AGT_ATR_SYNC_PATH=/opt/agt/examples/atr-community-rules/sync_atr_rules.py
python examples/atr-import/import_atr.py rules/
```

## Tests

```bash
pytest examples/atr-import/test_import_atr.py
```

The tests do not import `agent_os` directly. If the `agent_os` package is
installed in the environment, the YAML-shape validation uses
`agent_os.policies.schema.PolicyDocument` for stricter checks; otherwise it
falls back to structural validation against the same field set AGT's loader
expects (`name`, `version`, `rules[].name`, `rules[].condition`). All 12
tests pass either way.

## License

ATR is MIT-licensed. This example is part of AGT and inherits the AGT
repository license.
