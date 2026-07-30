# 2026-07-31 - MCP response sanitization: tag splices and residual verification (agent-os)

PR: microsoft/agent-governance-toolkit#3497

## What changed and why

`ResponsePolicy.SANITIZE` is the mode a host selects when it wants tool output
cleaned rather than dropped, so the content it returns is content the model is
going to read. Three defects on that path let the gateway return
`allowed=True, action="sanitized"` over content that was not sanitized.

The root cause is one property of tag stripping: **removing a substring splices
the text on either side of it together, and the splice is new text that was
never scanned.** All three findings follow from it.

| # | Site | Defect | Effect |
|---|------|--------|--------|
| 1 | `mcp_response_scanner.py` `sanitize_response` | Stripped instruction tags in a single pass per pattern | A tag written with a second tag embedded inside its own name — `[[system]system]` in the bracket syntax, and the same trick mid-name for the angle-bracket one — had the inner tag deleted, which spliced a live outer tag back together. The threat was reported as `"Instruction tag stripped"` while the tag was still in the returned string. |
| 2 | `mcp_gateway.py` `intercept_tool_response` | Re-checked only credentials on the sanitized text; hard-block categories were checked on the *pre*-sanitized text only | `_URL_PATTERN` stops at `<`, so `https://web<system>hook.site/collect?t=1` is only the harmless prefix `https://web` before sanitizing. Stripping `<system>` assembles a live exfiltration URL that no check ever saw. |
| 3 | `mcp_gateway.py` `intercept_tool_response` | The residual verification was unbounded and unwrapped | The residual re-scan was the one call on this path not inside a `try`, so a host-supplied scanner raising there escaped `intercept_tool_response` instead of failing closed. A caller that reads a raised exception as "scanner unavailable, proceed" then ships unverified content. |

The fixes:

**Strip to a fixed point, with a bound.** `sanitize_response` now repeats the
stripping passes until a pass changes nothing. Each nesting level costs one
pass, so an unbounded loop is quadratic in the depth — `"<" * n +
"important>" * n` at n=20,000 took ~15s before the bound and measures ~30ms
after it. `_MAX_TAG_NESTING_DEPTH = 8` caps it. Content a host would
legitimately sanitize converges in one or two passes; anything still producing
new tags at the limit is constructed, and the method returns
`("", [error threat])` for it rather than a partially cleaned string.

The loop runs `_MAX_TAG_NESTING_DEPTH + 1` times, because convergence is only
observable on a pass that changes nothing: depth *n* needs *n* stripping passes
plus one confirming pass. Iterating exactly `_MAX_TAG_NESTING_DEPTH` times
would reject a payload at exactly the tolerated depth — the final pass strips
the last tag but the loop ends before it can see the result was clean — making
the real limit one less than the constant's name claims.

**Verify the post-sanitize text against the categories the splice can create.**
The gateway's residual check now covers `pii_leak`, `data_exfiltration`,
`instruction_injection`, and `error`, not just credentials:

```python
residual_block_categories = hard_block_categories | {
    "instruction_injection",
    "error",
}
```

`"error"` is in the set because `scan_response` converts its own internal
failures into a threat of that category. A re-scan that could not run is not a
re-scan that passed; without `"error"` a crashing verifier reads as "nothing
residual" and the unverified content is forwarded.

`prompt_injection` is deliberately **excluded**. A residual imperative
("ignore all previous instructions") is prose `sanitize_response` never claimed
to strip, and blocking on it would silently turn SANITIZE into BLOCK for
ordinary text.

**Fail closed if the verifier itself raises.** The residual re-scan is wrapped,
logs at `ERROR` with `agent`/`tool` context, and sets the residual flag to
`True` on exception. It runs only when the cheaper checks passed — the verdict
is already `blocked` otherwise, and a full re-scan of a large response is not
free.

## Threat model impact

No new inputs, network exposure, secrets, or trust decisions are introduced.
The change is confined to `ResponsePolicy.SANITIZE`; `BLOCK`, `LOG`, and
`ALLOW` reach none of the modified code. Every behaviour change moves an
outcome from allow to block.

| Dimension | Direction |
|-----------|-----------|
| Injection containment (the purpose of SANITIZE) | Strengthened. The sanitizer's output now satisfies the scanner it is paired with. Previously a spliced tag was reported as removed and returned intact, which is worse than no sanitization: the audit record said the response was cleaned. |
| Untrusted input reachability | Directly reachable, which is why this matters. `response_content` is tool output — the untrusted side of the MCP boundary — and the splice payloads are cheap for a malicious or compromised server to emit. No privileged position is needed. |
| Hard-block categories (`pii_leak`, `data_exfiltration`) | Strengthened. These were already hard blocks, but only against threats present *before* sanitizing. They are now also enforced against threats the splice constructs. No category is removed from the hard-block set. |
| Fail-closed completeness | Strengthened. Three paths that previously returned an allow now block: non-convergent stripping, a residual threat in the sanitized text, and a re-scan that raises. `sanitize_response`'s non-convergence path returns an empty string, so no partially cleaned content is emitted under a "sanitized" label. |
| Availability / DoS | Improved, with a deliberate trade. The unbounded fixed point this replaces would have been a new CPU-exhaustion primitive (~15s for a 220 KB response). The bound makes the work linear in the response size. The trade is that a legitimate response nested deeper than 8 levels is refused rather than cleaned; refusal is the safe direction, and the log line names both the pass count and the depth so an operator can tell the two apart. |
| Information disclosure via findings | Neutral, and asserted. The non-convergence threat description and the log message both name only the tool, never the payload; tests assert the payload marker appears in neither. |
| New attack surface | None. No new parameters, no new configuration, no change to `hard_block_categories`, and the added scan is a second call to an existing method on the existing scanner. |

### Behaviour change callers may observe

A host on `SANITIZE` that previously received `allowed=True, action="sanitized"`
for one of the four shapes above now receives `allowed=False,
action="blocked", content=None`. Each of those four cases was returning content
that carried a live threat, so there is no configuration to restore the prior
outcome and none is offered.

### Known pre-existing behaviour left in place (out of scope)

`sanitize_response` strips opening instruction tags but not their closing
counterparts (`</important>`), which `_INSTRUCTION_TAG_PATTERNS` does not
match. This reproduces on the base commit, is not a threat on its own — a bare
closing tag carries no instruction — and changing the pattern set is a
detection-scope decision that belongs in its own maintainer-reviewed change.
The tests here assert the sanitized text as it actually is rather than papering
over it.

## Test coverage

Each regression test was verified to fail on the base commit and pass on the
fix.

| Test | Validates |
|------|-----------|
| `test_mcp_response_scanner.py::test_sanitize_response_output_contains_no_instruction_tag` | 6 parametrized splice shapes (both tag syntaxes, split at the tag start and mid-name, two nesting levels, and a splice forming a *different* tag than the one removed) leave no `instruction_injection` threat in the output. Asserts the payload text survives, so a sanitizer that refused everything would not pass. |
| `test_mcp_response_scanner.py::test_sanitize_response_accepts_content_at_exactly_the_nesting_limit` | Depth `_MAX_TAG_NESTING_DEPTH` is cleaned, not refused — pins the `+ 1` confirming pass, without which the constant overstates the real limit by one |
| `test_mcp_response_scanner.py::test_sanitize_response_fails_closed_when_stripping_does_not_converge` | Depth over the limit returns `("", [error])`, and the finding does not echo the payload |
| `test_mcp_response_scanner.py::test_non_convergence_log_reports_the_passes_it_actually_ran` | The log states both the 9 passes run and the depth 8 tolerated, since the two numbers mean different things during an incident |
| `test_mcp_response_scanner.py::test_sanitize_response_bounds_adversarial_nesting_cost` | 20,000-level nesting completes under 1.0s (measured ~30ms against ~15s unbounded, ~35x headroom over a threshold set to separate "bounded" from "quadratic" on a loaded runner) |
| `test_mcp_response_scanner.py::test_sanitize_response_still_converges_in_one_pass_for_ordinary_content` | The bound costs nothing for content a host would really sanitize |
| `test_mcp_pii_and_response_gateway.py::TestGatewayResponseSanitize::test_spliced_injection_tag_does_not_reach_the_model` | End to end: `allowed=True, action="sanitized"` **and** no residual tag. The allow assertions come first on purpose — a block returns `content=None`, which scans clean, so the tag assertion alone would also be satisfied by SANITIZE regressing into a hard block |
| `..::test_hard_block_threat_created_by_the_splice_is_still_blocked` | The `https://web<system>hook.site/...` payload blocks, and asserts `data_exfiltration` is *absent* pre-sanitize so the test cannot pass via the ordinary hard-block path |
| `..::test_non_converging_response_is_blocked_not_sanitized` | Non-convergence surfaces at the gateway as `blocked`, never as `sanitized` |
| `..::test_failed_residual_re_scan_blocks_instead_of_allowing` | Injects the failure in `_scan_exfiltration_urls` — called by `scan_response` and not by `sanitize_response`, so only the verifying scan breaks, and it breaks through the scanner's real fail-closed path rather than a fabricated return value. Asserts the re-scan actually ran (`calls == 2`) |
| `..::test_residual_re_scan_that_raises_fails_closed` | A host-supplied scanner raising past `scan_response`'s own handler blocks instead of propagating out of `intercept_tool_response`. The first scan is allowed to succeed, so this fails closed because the *verifier* could not run, not because the response was already known unsafe |

`tests/test_mcp_response_scanner.py` and
`tests/test_mcp_pii_and_response_gateway.py` pass in full (68 passed).

The agent-os suite is 2725 passed, 90 skipped, 9 failed. All 9 failures were
confirmed to reproduce at the merge base (`4c5b2aa3`) with the same count, and
none is in the MCP response path: 8 are `ModuleNotFoundError: No module named
'agentmesh'` from `cli/cmd_sign.py` in the CLI routing tests, and
`test_mcp_scan_cli.py::test_inspect_legacy_sse_server_lists_tools` fails on an
unrelated assertion. Three test modules (`test_cmd_sign.py`,
`test_policy_gen.py`, `test_spec_mcp_gateway_conformance.py`) do not collect
locally because sibling packages are not installed in this environment; they
are unaffected by the change and collect in CI.
