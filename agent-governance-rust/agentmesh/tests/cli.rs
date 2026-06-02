// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration / BDD tests for the feature-gated `agt` operator CLI.
//!
//! The whole file is gated behind the `cli` feature so that a default
//! `cargo test -p agentmesh` (no `--features cli`) neither builds the binary
//! nor runs these tests, which call `Command::cargo_bin("agt")`.
#![cfg(feature = "cli")]

use agentmesh::types::AuditEntry;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// A well-formed policy profile (matches `PolicyProfile`: version + agent + policies).
const VALID_POLICY: &str = r#"
version: "1.0"
agent: test-agent
policies:
  - name: allow-read
    type: capability
    allowed_actions:
      - "data.read"
    denied_actions:
      - "shell:*"
"#;

fn agentmesh() -> Command {
    Command::cargo_bin("agt").expect("cli binary builds with --features cli")
}

/// Write `contents` to `<tmp>/<name>` and return the absolute path string.
fn write_fixture(tmp: &TempDir, name: &str, contents: &str) -> String {
    let path = tmp.path().join(name);
    fs::write(&path, contents).expect("write fixture");
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Feature: policy CLI
// ---------------------------------------------------------------------------

#[test]
fn policy_validate_ok() {
    // Given: a well-formed policy YAML.
    // When: `agt policy validate <path>`.
    // Then: exit 0 and stdout confirms the policy is valid.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args(["policy", "validate", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("valid"));
}

#[test]
fn policy_validate_malformed_exit1() {
    // Given: a structurally malformed policy (missing required `version`/`agent`).
    // When: validate.
    // Then: exit 1 with a structured `error:` on stderr; no panic.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "bad.yaml", "policies: [this is: not valid: yaml::");

    agentmesh()
        .args(["policy", "validate", &path])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn policy_validate_missing_file_exit1() {
    // Given: a path that does not exist.
    // When: validate.
    // Then: fail closed with exit 1 and an IO error on stderr.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("does-not-exist.yaml");

    agentmesh()
        .args(["policy", "validate", &path.to_string_lossy()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn policy_explain_decision() {
    // Given: a valid policy that allows `data.read`.
    // When: explain with --action data.read.
    // Then: exit 0 and stdout reports an allow decision.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args(["policy", "explain", &path, "--action", "data.read"])
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}

#[test]
fn policy_explain_denied_action_still_exit0() {
    // Given: a valid policy denying `shell:*`.
    // When: explain with --action shell:rm.
    // Then: exit 0 (explain reports the decision; a deny is not a CLI failure),
    //       stdout reports a deny decision.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args(["policy", "explain", &path, "--action", "shell:rm"])
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn policy_explain_bad_context_exit1() {
    // Given: a valid policy.
    // When: explain with an invalid --context JSON.
    // Then: exit 1 — invalid input is surfaced, never silently ignored.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args([
            "policy",
            "explain",
            &path,
            "--action",
            "data.read",
            "--context",
            "{not json",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn unknown_subcommand_exit2() {
    // Given: an unknown subcommand.
    // When: invoked.
    // Then: clap usage error → exit 2.
    agentmesh().args(["policy", "frobnicate"]).assert().code(2);
}

#[test]
fn garbage_policy_fails_closed_no_panic() {
    // Abuse case: a large garbage file must exit 1 with a structured
    // error, terminate promptly, and never panic.
    let tmp = TempDir::new().unwrap();
    let garbage = "\u{fffd}".repeat(100_000);
    let path = write_fixture(&tmp, "garbage.yaml", &garbage);

    agentmesh()
        .args(["policy", "validate", &path])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

// ---------------------------------------------------------------------------
// Feature: audit CLI
// ---------------------------------------------------------------------------

/// Build a JSON array of `n` audit entries matching `AuditLogger::export_json`'s shape.
fn audit_json(n: u64) -> String {
    let entries: Vec<serde_json::Value> = (0..n)
        .map(|seq| {
            serde_json::json!({
                "seq": seq,
                "timestamp": format!("2026-05-22T00:00:{:02}Z", seq % 60),
                "agent_id": format!("agent-{seq}"),
                "action": "data.read",
                "decision": "allow",
                "previous_hash": format!("{:064x}", seq),
                "hash": format!("{:064x}", seq + 1),
            })
        })
        .collect();
    serde_json::to_string(&entries).unwrap()
}

#[test]
fn audit_tail_last_n() {
    // Given: an audit file with 50 entries.
    // When: `audit tail --limit 5`.
    // Then: exit 0; the last 5 entries (seq 45..=49) are printed.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", &audit_json(50));

    agentmesh()
        .args(["audit", "tail", &path, "--limit", "5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent-49"))
        .stdout(predicate::str::contains("agent-45"))
        .stdout(predicate::str::contains("agent-44").not());
}

#[test]
fn audit_tail_default_limit() {
    // Given: 50 entries. When: tail with no --limit. Then: 20 entries (default).
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", &audit_json(50));

    agentmesh()
        .args(["audit", "tail", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent-49"))
        .stdout(predicate::str::contains("agent-30"))
        .stdout(predicate::str::contains("agent-29").not());
}

#[test]
fn audit_tail_limit_exceeds_len_no_panic() {
    // Resource bound: file with 3 entries, --limit 100 → prints 3, no panic/over-read.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", &audit_json(3));

    agentmesh()
        .args(["audit", "tail", &path, "--limit", "100"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent-0"))
        .stdout(predicate::str::contains("agent-2"));
}

#[test]
fn audit_tail_empty_file() {
    // Empty state: an empty JSON array exits 0 with a clear "no entries" message.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", "[]");

    agentmesh()
        .args(["audit", "tail", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("no entries"));
}

#[test]
fn audit_tail_malformed_exit1() {
    // Abuse case: truncated/garbage JSON exits 1 with a structured
    // error and never panics.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", "[{\"seq\": 0, ");

    agentmesh()
        .args(["audit", "tail", &path])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn audit_tail_missing_file_exit1() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("nope.json");

    agentmesh()
        .args(["audit", "tail", &path.to_string_lossy()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn audit_export_ndjson_line_per_entry() {
    // Given: 3 entries. When: export --format ndjson.
    // Then: exit 0; exactly 3 lines, each parses as an AuditEntry.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", &audit_json(3));

    let out = agentmesh()
        .args(["audit", "export", &path, "--format", "ndjson"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "ndjson must emit one line per entry");
    for line in lines {
        serde_json::from_str::<AuditEntry>(line)
            .unwrap_or_else(|e| panic!("each ndjson line must parse as AuditEntry: {e} ({line})"));
    }
}

#[test]
fn audit_export_json_valid_array() {
    // export --format json emits a JSON array that parses back into Vec<AuditEntry>.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "audit.json", &audit_json(3));

    let out = agentmesh()
        .args(["audit", "export", &path, "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let parsed: Vec<AuditEntry> =
        serde_json::from_slice(&out).expect("json export is a valid array");
    assert_eq!(parsed.len(), 3);
}

// ---------------------------------------------------------------------------
// Feature: trust CLI
// ---------------------------------------------------------------------------

#[test]
fn trust_set_then_show_roundtrip() {
    // Given: an empty (missing) store.
    // When: set a1=800, then show a1.
    // Then: both exit 0; show reports ~800 and the Trusted tier.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");
    let store = store.to_string_lossy().into_owned();

    agentmesh()
        .args(["trust", "set", "a1", "800", "--store", &store])
        .assert()
        .success();
    agentmesh()
        .args(["trust", "show", "a1", "--store", &store])
        .assert()
        .success()
        .stdout(predicate::str::contains("800"))
        .stdout(predicate::str::contains("Trusted"));
}

#[test]
fn trust_show_unknown_agent_missing_store() {
    // Empty state: a missing store is a valid empty store; show reports the
    // default initial score without crashing.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");

    agentmesh()
        .args([
            "trust",
            "show",
            "ghost",
            "--store",
            &store.to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("500"));
}

#[test]
fn trust_set_out_of_range_exit1() {
    // Abuse case: score > 1000 exits 1 and does NOT silently clamp/persist.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");
    let store_s = store.to_string_lossy().into_owned();

    agentmesh()
        .args(["trust", "set", "a1", "5000", "--store", &store_s])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
    // Store must not have been created/modified.
    assert!(!store.exists(), "out-of-range set must not write the store");
}

#[test]
fn trust_set_negative_score_exit2() {
    // Invalid input: a negative score is rejected at parse time (clap, exit 2).
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");

    agentmesh()
        .args([
            "trust",
            "set",
            "a1",
            "-3",
            "--store",
            &store.to_string_lossy(),
        ])
        .assert()
        .code(2);
}

#[test]
fn trust_set_parentdir_path_exit1() {
    // A `..` store path is rejected with a visible error, not a silent no-op
    // (the library's persistence silently skips `..` paths).
    agentmesh()
        .args(["trust", "set", "a1", "800", "--store", "../escape.json"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn trust_show_corrupt_store_exit1() {
    // Abuse case: a corrupt store exits 1 (not a silent default) and the
    // original bytes are left intact.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");
    let garbage = b"\x00\x01 not json at all }{";
    fs::write(&store, garbage).unwrap();

    agentmesh()
        .args(["trust", "show", "a1", "--store", &store.to_string_lossy()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
    assert_eq!(
        fs::read(&store).unwrap(),
        garbage,
        "corrupt store must be untouched"
    );
}

#[test]
fn trust_set_corrupt_store_not_clobbered() {
    // `set` must pre-validate the existing store and refuse (exit 1) rather than
    // overwrite a garbage file.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json");
    let garbage = b"\x00\x01 not json at all }{";
    fs::write(&store, garbage).unwrap();

    agentmesh()
        .args([
            "trust",
            "set",
            "a1",
            "800",
            "--store",
            &store.to_string_lossy(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
    assert_eq!(
        fs::read(&store).unwrap(),
        garbage,
        "garbage store must not be clobbered"
    );
}

#[cfg(unix)]
#[test]
fn trust_set_unwritable_store_exit1() {
    // When the library silently drops the write (unwritable dir), the CLI's
    // read-back verification must surface it as exit 1 — never a false exit 0.
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let ro_dir = tmp.path().join("ro");
    fs::create_dir(&ro_dir).unwrap();
    let store = ro_dir.join("trust.json");
    // Make the directory read-only so the write cannot land.
    fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let result = agentmesh()
        .args([
            "trust",
            "set",
            "a1",
            "800",
            "--store",
            &store.to_string_lossy(),
        ])
        .assert()
        .code(1);
    // Restore perms so TempDir cleanup can remove the directory.
    let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755));
    let _ = result;
}

#[test]
fn trust_set_persists_across_processes() {
    // Persistence: a value set in one invocation is visible in a separate invocation.
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json").to_string_lossy().into_owned();

    agentmesh()
        .args(["trust", "set", "a1", "700", "--store", &store])
        .assert()
        .success();
    agentmesh()
        .args(["trust", "show", "a1", "--store", &store])
        .assert()
        .success()
        .stdout(predicate::str::contains("700"));
}

#[test]
fn trust_set_tier_boundary_900() {
    // Happy path: a score of 900 reports the VerifiedPartner tier (matches
    // TrustTier::from_score(900)).
    let tmp = TempDir::new().unwrap();
    let store = tmp.path().join("trust.json").to_string_lossy().into_owned();

    agentmesh()
        .args(["trust", "set", "a1", "900", "--store", &store])
        .assert()
        .success();
    agentmesh()
        .args(["trust", "show", "a1", "--store", &store])
        .assert()
        .success()
        .stdout(predicate::str::contains("VerifiedPartner"));
}

// ---------------------------------------------------------------------------
// Feature: agt check
// ---------------------------------------------------------------------------

#[test]
fn check_allow_exit0() {
    // Given: a policy allowing data.read.
    // When: check with an input requesting data.read.
    // Then: exit 0; stdout JSON reports allowed=true.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args([
            "check",
            "--policy",
            &path,
            "--input",
            r#"{"action":"data.read"}"#,
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"allowed\":true"));
}

#[test]
fn check_deny_exit1() {
    // Given: a policy denying shell:*.
    // When: check requesting shell:rm.
    // Then: exit 1 (a deny is reflected in the exit code, not an error); allowed=false.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args([
            "check",
            "--policy",
            &path,
            "--input",
            r#"{"action":"shell:rm"}"#,
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"allowed\":false"));
}

#[test]
fn check_with_context_exit0() {
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args([
            "check",
            "--policy",
            &path,
            "--input",
            r#"{"action":"data.read","context":{"trust_score":800}}"#,
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"decision\":\"allow\""));
}

#[test]
fn check_bad_input_exit2() {
    // Abuse case: malformed --input JSON must exit 2 and never default to allow.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args(["check", "--policy", &path, "--input", "{not json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn check_missing_action_exit2() {
    // Input validation: an input object without `action` is rejected (exit 2), not allowed.
    let tmp = TempDir::new().unwrap();
    let path = write_fixture(&tmp, "policy.yaml", VALID_POLICY);

    agentmesh()
        .args(["check", "--policy", &path, "--input", "{}"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn check_missing_policy_exit2() {
    // Dependency failure: a missing/invalid policy file exits 2.
    let tmp = TempDir::new().unwrap();
    let missing = tmp.path().join("nope.yaml");

    agentmesh()
        .args([
            "check",
            "--policy",
            &missing.to_string_lossy(),
            "--input",
            r#"{"action":"data.read"}"#,
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn help_lists_all_command_groups() {
    // Compatibility: the renamed `agt` binary exposes check + policy + audit + trust.
    agentmesh()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("check"))
        .stdout(predicate::str::contains("policy"))
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("trust"));
}
