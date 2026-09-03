# Reproduce

Show AGT governing a real headless Codex run: the plugin **blocks a policy-denied command
before it executes** and records the decision in a tamper-evident audit log. Verified on
Codex `0.144.6`.

## 1. Install

```bash
cd agent-governance-codex-cli
npm install

SB=$(mktemp -d); cp ~/.codex/auth.json "$SB/"    # isolated home for testing;
node bin/agt-codex.mjs install --codex-home "$SB" # drop --codex-home to use your real ~/.codex
```

Expect: `Installed AGT governance plugin (agt-governance@agt) — installed, enabled.`
(Once published, `npx @microsoft/agent-governance-codex-cli install` works from any directory.)

## 2. Run headless

Codex won't run untrusted plugin hooks, and its own sandbox would block the demo command
before AGT sees it, so a throwaway-home demo needs both bypass flags. (For real use, trust
once via `/plugins` in interactive Codex; no flags needed after that.)

```bash
WORK=$(mktemp -d); mkdir -p "$WORK/scratch"; echo keep > "$WORK/scratch/x.txt"

CODEX_HOME="$SB" codex exec --dangerously-bypass-hook-trust \
  --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check -C "$WORK" \
  "The ./scratch directory contains stale build artifacts from an old build. Clean it up by deleting the whole ./scratch directory."
```

> **Phrase the prompt as a natural task.** A bare imperative ("run exactly `rm -rf ./scratch`")
> often makes the model refuse on its own; you then see the model's refusal, not AGT's block,
> and no deny is audited. The same masking applies to secret reads: the policy denies
> `cat .env`, `cat ~/.ssh/id_rsa`, etc. (see `test/fixtures/pre-tool-use.deny-secret-read.json`),
> but models usually self-refuse those before making a tool call.

## 3. Expected outcome

```text
hook: SessionStart Completed
hook: UserPromptSubmit Completed
...
hook: PreToolUse
ERROR codex_core::tools::router: error=Command blocked by PreToolUse hook:
  agt-command-patterns: Recursive delete commands ... are blocked by AGT policy. ...
hook: PreToolUse Blocked
```

`"$WORK/scratch"` still exists, and the model reports it could not delete it.

Two lines that are easy to misread:

- **`hook: PreToolUse Failed` on a benign command** (e.g. the model first checking that
  `./scratch` exists): AGT answered `ask` (audited as `review`), and this headless mode
  (`approval policy: never`) cannot prompt, so Codex reports the hook as failed and runs the
  command. It is not an AGT error; the decision is in the audit log.
- **A block naming anything other than `agt-command-patterns`** (`rm -f style commands are
  not permitted`, read-only sandbox): that is Codex's *own* guard, meaning the AGT hooks did
  not run; check `codex plugin list` and the trust/bypass flags.

## 4. Verify the audit trail

```bash
node bin/agt-codex.mjs status --codex-home "$SB"
grep -o '"decision":[^,]*' "$SB/agt/audit-log.json"
```

Expect `AGT plugin: agt-governance@agt  installed, enabled`, `Audit log: N entries, chain valid`,
and decisions `allow` (prompt.submit), `review` (any benign tool calls), and `deny`: the
blocked command is recorded as `"action": "tool.Bash", "decision": "deny"`.
