# Pre-Commit Hook Rollout Template

> Drop-in configuration for enforcing AGT governance checks at commit time.
> Copy this into any governed repository and customize for your stack.

## Quick Start

### 1. Install pre-commit

```bash
pip install pre-commit
```

### 2. Add `.pre-commit-config.yaml` to your repo root

```yaml
# .pre-commit-config.yaml — AGT governance hooks
# See https://github.com/microsoft/agent-governance-toolkit

repos:
  # ── AGT policy validation ────────────────────────────────
  - repo: local
    hooks:
      - id: agt-validate
        name: AGT Policy Validation
        entry: bash -c 'python -m agent_os.cli validate --strict'
        language: system
        files: '(governance\.ya?ml|policies/.*\.ya?ml)$'
        pass_filenames: false

      - id: agt-doctor
        name: AGT Health Check
        entry: bash -c 'python -m agent_os.cli doctor --quiet'
        language: system
        pass_filenames: false
        stages: [pre-push]

  # ── Governance metadata ───────────────────────────────────
  - repo: local
    hooks:
      - id: agency-json-required
        name: Plugin agency.json Check
        entry: bash -c '
          for dir in plugins/*/; do
            if [ -d "$dir" ] && [ ! -f "${dir}agency.json" ]; then
              echo "❌ Missing agency.json in $dir"
              exit 1
            fi
          done
        '
        language: system
        pass_filenames: false

  # ── Secret scanning ──────────────────────────────────────
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  # ── Quality gates (mirroring CI) ─────────────────────────
  - repo: local
    hooks:
      - id: no-stubs
        name: No TODO/FIXME Stubs
        entry: bash -c '
          PATTERN="TODO|FIXME|HACK|XXX|raise NotImplementedError|todo!()|unimplemented!()"
          STAGED=$(git diff --cached --diff-filter=ACMR -U0 -- "*.py" "*.ts" "*.rs" "*.cs" "*.go" ":!*test*" | grep -E "^\+[^+]" || true)
          if [ -n "$STAGED" ]; then
            HITS=$(echo "$STAGED" | grep -iE "$PATTERN" || true)
            if [ -n "$HITS" ]; then
              echo "❌ Stub markers in staged code:"
              echo "$HITS"
              exit 1
            fi
          fi
        '
        language: system
        pass_filenames: false

      - id: no-custom-crypto
        name: No Raw Crypto Outside Security Modules
        entry: bash -c '
          PATTERN="from cryptography|from Crypto\.|import hashlib|import hmac|crypto\.subtle|crypto\.createHash|use ring::|use ed25519_dalek|System\.Security\.Cryptography"
          STAGED=$(git diff --cached --diff-filter=ACMR -U0 -- "*.py" "*.ts" "*.rs" "*.cs" "*.go" ":!agent-governance-python/agent-mesh/**" ":!*encryption*" ":!*security*" ":!*test*" | grep -E "^\+[^+]" || true)
          if [ -n "$STAGED" ]; then
            HITS=$(echo "$STAGED" | grep -E "$PATTERN" || true)
            if [ -n "$HITS" ]; then
              echo "❌ Raw crypto outside security modules:"
              echo "$HITS"
              exit 1
            fi
          fi
        '
        language: system
        pass_filenames: false
```

### 3. Install the hooks

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

### 4. Run against all files (first time)

```bash
pre-commit run --all-files
```

## Customization

### Adjusting for your repo

| Hook | When to customize |
|------|-------------------|
| `agt-validate` | Change `--strict` to `--permissive` during initial rollout |
| `agency-json-required` | Adjust `plugins/*/` path to match your plugin directory |
| `no-stubs` | Add patterns specific to your framework |
| `no-custom-crypto` | Adjust allowed paths for your security module locations |

### Phased rollout

1. **Week 1**: Install with `--permissive` mode — hooks warn but don't block
2. **Week 2**: Switch to `--strict` for policy validation only
3. **Week 3**: Enable all hooks as blocking
4. **Week 4**: Graduate to full blocking per the
   [graduation checklist](advisory-to-blocking-graduation.md)

## CI Mirror

These hooks mirror the CI quality gates in `.github/workflows/quality-gates.yml`.
The hooks catch issues at commit time; CI catches anything that bypasses hooks
(force push, direct GitHub edits, etc.).

---

*Closes #1431*
