# AgentDojo benchmark harness

This directory contains an opt-in Python harness for measuring AgentControlSpecification behavior on a representative AgentDojo banking subset. It keeps benchmark code outside the Rust workspace, uses a local requirements file, wraps the AgentDojo pipeline, and reports baseline results beside guarded results.

## Files

`acs_agentdojo_bench/runner.py` provides the CLI and result table. `acs_agentdojo_bench/pipeline.py` wraps AgentDojo tool execution with ACS input, pre tool call, and post tool call checks. `manifest.yaml` is the benchmark policy contract. `test_smoke.py` imports the harness and validates the opt-in skip path.

## Setup

Create an isolated environment from this directory or from the repository root.

```bash
python -m venv .venv-agentdojo
. .venv-agentdojo/bin/activate
python -m pip install -r benchmarks/agentdojo/requirements.txt
python -m pip install -e sdk/python
```

The benchmark expects model credentials in the repository root `.env` file. Source that file before running live work.

```bash
set -a && . ./.env && set +a
export ACS_AGENTDOJO_ENABLE=1
```

`OPENAI_API_KEY` enables the default OpenAI path. `AZURE_OPENAI_API_KEY` is accepted by the gate for Azure based local configuration.

## Run

Use the default command for a small banking subset. It runs baseline first and ACS second.

```bash
PYTHONPATH=benchmarks/agentdojo python -m acs_agentdojo_bench.runner
```

Use explicit task ids to change the subset.

```bash
PYTHONPATH=benchmarks/agentdojo python -m acs_agentdojo_bench.runner \
  --user-task user_task_0 \
  --injection-task injection_task_0 \
  --model gpt-4o-mini
```

Use `--mode baseline` or `--mode acs` to run one side. Use `--no-write` to suppress JSONL and CSV output.

## Interpretation

The table reports ASR as the mean of AgentDojo security outcomes where true means the injected attacker goal succeeded. Lower ASR is better. Injection utility is the mean of utility outcomes under injected conditions. Higher injection utility is better when ASR stays low. The baseline mode uses the plain AgentDojo pipeline. The ACS mode enforces `manifest.yaml` before user input reaches the agent, before tool execution, and after tool output is returned to the model.

The benchmark is skipped unless `ACS_AGENTDOJO_ENABLE=1` and model credentials are present. This keeps ordinary test and CI environments deterministic when network access or credentials are absent.

## Results

Two complementary runs over the AgentDojo banking suite with the `important_instructions`
attack (which injects attacker goals into untrusted tool output). ACS enforces
`manifest.yaml` at input, pre tool call, and post tool call; the policy taints the
session when a tool result carries injection markers and denies destructive banking
tools (`send_money`, `schedule_transaction`, `update_scheduled_transaction`,
`update_password`, `update_user_info`) while a tainted result is in scope.

Deterministic harness (`--llm scripted`, replays ground-truth so every injection is
forced to land — this isolates the policy from model susceptibility):

| mode | benign | attacked utility | ASR |
| --- | --- | --- | --- |
| baseline | 0.800 | 0.800 | **1.000** |
| acs | 0.800 | 0.000 | **0.000** |

ACS drives attack success rate from 1.000 to 0.000 **at zero benign-utility cost**
(0.800 → 0.800): every benign task that passed without ACS still passes with it.

Live (Azure deployment, a strong reasoning model that resists these injections unaided,
so baseline ASR is already 0):

| mode | benign | attacked utility | ASR |
| --- | --- | --- | --- |
| baseline | 0.750 | 0.750 | 0.000 |
| acs | 0.750 | 0.125 | 0.000 |

Live, ACS preserves benign utility exactly (0.750 → 0.750) and holds ASR at 0, while
additionally refusing the injected destructive tool calls the model was steered toward
(reflected in the lower attacked-utility number — those are defensive denials, not
benign-task regressions).

> The `model` column in the printed table shows a cosmetic label
> (`gpt-4o-mini-2024-07-18`); the live deployment is whatever `AZURE_OPENAI_DEPLOYMENT`
> points at. Reproduce the deterministic result with `--mode both --llm scripted`; the
> live result additionally needs Azure credentials sourced from `.env`.
