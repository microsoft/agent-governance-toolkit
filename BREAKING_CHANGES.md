# Breaking Changes

This file records breaking changes that require consumer-side updates. Newer
entries appear first.

---

## Composite actions: `toolkit-version` is now **required**

**Date:** TBD (next release of `microsoft/agent-governance-toolkit`)

**Affected:**

- `microsoft/agent-governance-toolkit/action`
- `microsoft/agent-governance-toolkit/action/security-scan`
- `microsoft/agent-governance-toolkit/action/governance-attestation`

**What changed:**

The `toolkit-version` input was previously optional and defaulted to the
latest published toolkit release at action-update time. That behaviour created
a silent supply-chain coupling: a compromised, yanked, or unintentionally
broken toolkit release could land in any consumer's CI on the next workflow
run, with no version pin under the consumer's control.

`toolkit-version` is now **required**, and the action validates the value
against a strict regex that accepts only `X.Y.Z`, `X.Y.ZaN`, `X.Y.ZbN`, and
`X.Y.ZrcN`. Floating refs (`3.7.*`, `>=3.7`), post-releases (`3.7.0.post1`),
dev-releases (`3.7.0.dev0`), local-version identifiers (`3.7.0+local`), URL /
VCS references, and environment markers are all rejected.

**Why:**

This closes a class of supply-chain finding raised during the
`jackbatzner/harden-ci-review-automation` review: an attacker who can
republish or yank a toolkit release should not automatically execute in
consumer pipelines, and the version pin must be explicit and auditable in
the consumer's repository.

**How to migrate:**

1. **Pin the action to the major tag you were already using.** The major tag
   (e.g. `@v3`) continues to point at the latest release within that major,
   so the toolkit-version requirement does not break your pipeline at
   action-update time:

   ```yaml
   - uses: microsoft/agent-governance-toolkit/action@v3
     with:
       toolkit-version: "3.7.0"          # <-- now required
   ```

2. **Bump `toolkit-version` deliberately** when a new release ships. Treat
   it the same way you would a pinned npm or pip dependency: review the
   changelog and the release notes before bumping.

3. **Consider Dependabot** for the version-bump itself. `toolkit-version` is
   a string, so a small ecosystem-specific updater or a regex-based custom
   updater is the easiest fit.

If your workflow run fails with:

```
::error::toolkit-version must be an exact release or pre-release (e.g. 3.7.0 or 3.7.0rc1); got: ...
```

then the value you supplied does not match the accepted syntax. See
[`action/README.md`](action/README.md#accepted-version-syntax) for the full
list of accepted and rejected forms.

**Operational note:** the action's own version (`@v3`, `@v3.7.0`, or a
commit SHA) is independent of `toolkit-version`. Pinning the action to a
commit SHA is recommended for high-trust pipelines (see GitHub's
[hardening guide for third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)).
