<!-- BEGIN MICROSOFT SECURITY.MD V1.0.0 BLOCK -->

## Security

Microsoft takes the security of our software products and services seriously, which
includes all source code repositories in our GitHub organizations.

**Please do not report security vulnerabilities through public GitHub issues.**

For security reporting information, locations, contact information, and policies,
please review the latest guidance for Microsoft repositories at
[https://aka.ms/SECURITY.md](https://aka.ms/SECURITY.md).

<!-- END MICROSOFT SECURITY.MD BLOCK -->

## Security Advisories

### CostGuard Organization Kill Switch Bypass (Fixed in v2.1.0)

**Severity:** High
**Affected versions:** < 2.1.0
**Fixed in:** v2.1.0 (PR #272)

A crafted input using IEEE 754 special values (NaN, Infinity, negative numbers) to
CostGuard budget parameters could bypass the organization-level kill switch, allowing
agents to continue operating after the budget threshold was exceeded.

**Fix:** Input validation now rejects NaN/Inf/negative values. The `_org_killed` flag
persists kill state permanently — once the organization budget threshold is crossed,
all agents are blocked including newly created ones.

**Recommendation:** Upgrade to v2.1.0 or later. No workaround exists for earlier versions.

### Thread Safety Fixes (Fixed in v2.1.0)

**Severity:** Medium
**Affected versions:** < 2.1.0
**Fixed in:** v2.1.0

Four independent thread safety issues were fixed in security-critical paths:
- CostGuard breach history: unbounded growth + missing lock (#253)
- VectorClock: race condition under concurrent access (#243)
- ErrorBudget._events: unbounded deque without size limit (#172)
- .NET SDK: thread safety, caching, disposal sweep (#252)

**Recommendation:** Upgrade to v2.1.0 or later if running under concurrent agent load.
