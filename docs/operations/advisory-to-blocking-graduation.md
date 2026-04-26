# Advisory-to-Blocking Graduation Checklist

> Use this checklist when graduating a repository from **advisory** governance
> (warn-only, non-blocking) to **blocking** governance (CI failures, merge
> prevention).

## Prerequisites

- [ ] Repository has been running advisory governance for **≥ 2 weeks** with
      no false-positive alerts that would block legitimate work
- [ ] All existing CI workflows pass with governance checks enabled
- [ ] Repository maintainers have acknowledged the graduation timeline
- [ ] CODEOWNERS file includes at least one governance-aware reviewer

## Policy Configuration

- [ ] `governance.yaml` (or equivalent) exists at repo root with:
  - `mode: strict` (deny-by-default for tool calls)
  - `audit: required` (all governed actions logged)
  - Explicit allow rules for every permitted tool/action
- [ ] Policy files have been reviewed by security team
- [ ] No `permissive` mode overrides remain in production config
- [ ] All custom policy rules have corresponding test cases

## CI/CD Integration

- [ ] Pre-commit hooks installed and documented in `CONTRIBUTING.md`:
  - Policy validation (`agt validate`)
  - Secret scanning
  - Governance metadata checks
- [ ] CI pipeline includes blocking governance checks:
  - `agt audit` — verify policy coverage
  - `agt doctor` — verify component health
  - Quality gates from `ci/` scripts (no-stubs, no-custom-crypto, etc.)
- [ ] Branch protection requires governance checks to pass before merge
- [ ] Dependabot/Renovate configured with governance-aware merge policies

## Security & Compliance

- [ ] `SECURITY.md` exists with vulnerability reporting instructions
- [ ] `.github/copilot-instructions.md` includes governance review requirements
- [ ] Security audit doc exists for any capability-introducing changes
- [ ] Compliance mapping relevant to the repo's domain is documented

## Monitoring & Rollback

- [ ] Governance dashboard accessible to repo maintainers
- [ ] Alert thresholds configured for:
  - Unusual deny rates (may indicate false positives)
  - Audit log gaps (may indicate bypass attempts)
  - Policy evaluation latency spikes
- [ ] Rollback procedure documented: how to revert to advisory mode if
      blocking causes issues
- [ ] On-call rotation includes someone who can modify governance config

## Communication

- [ ] Announcement posted to repo's discussion/channel **≥ 1 week** before
      graduation date
- [ ] Migration guide for contributors (what changes for their workflow)
- [ ] FAQ addressing common concerns (false positives, overrides, exceptions)

## Post-Graduation

- [ ] Monitor deny rates for first 48 hours — high rates may indicate
      missing allow rules, not malicious activity
- [ ] Review and close any advisory-mode tracking issues
- [ ] Update repo's governance status in the cross-repo inventory
- [ ] Schedule 30-day review to assess blocking mode effectiveness

---

*Closes #1432*
