// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guard the shim's crates.io identity after the ACS retarget.
//!
//! `0.3.1-beta.0` is already the pre-retarget embedded engine on crates.io.
//! Publishing this compatibility crate under that version would collide with
//! a different artifact. The shim's `#[deprecated(since = "0.3.2-beta.0")]`
//! attributes name the intended next identity. Consumer lockfiles must record
//! this path crate, not the published cedar-policy/ureq engine.

use std::fs;
use std::path::{Path, PathBuf};

const COLLIDING_VERSION: &str = "0.3.1-beta.0";
const SHIM_VERSION: &str = "0.3.2-beta.0";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core lives at policy-engine/core")
        .to_path_buf()
}

fn package_stanza(lockfile: &str, package: &str) -> Option<&str> {
    let header = format!("name = \"{package}\"\n");
    let start = lockfile.find(&header)?;
    let rest = &lockfile[start..];
    let end = rest.find("\n[[package]]").unwrap_or(rest.len());
    Some(&rest[..end])
}

fn package_version(stanza: &str) -> Option<&str> {
    let marker = "version = \"";
    let start = stanza.find(marker)? + marker.len();
    let end = stanza[start..].find('"')?;
    Some(&stanza[start..start + end])
}

#[test]
fn core_shim_version_does_not_collide_with_published_embedded_engine() {
    assert_ne!(
        env!("CARGO_PKG_VERSION"),
        COLLIDING_VERSION,
        "0.3.1-beta.0 is already the pre-retarget embedded engine on crates.io"
    );
    assert_eq!(
        env!("CARGO_PKG_VERSION"),
        SHIM_VERSION,
        "publish the shim as the version already named by #[deprecated(since)]"
    );
}

#[test]
fn consumer_lockfiles_record_the_path_shim_not_the_published_engine() {
    let root = repo_root();
    let lockfiles = [
        "policy-engine/Cargo.lock",
        "agent-governance-rust/Cargo.lock",
        "policy-engine/examples/coding_agent/app/Cargo.lock",
        "benchmarks/prompt-injection/harness/agt-rules-baseline/Cargo.lock",
    ];

    for rel in lockfiles {
        let text = fs::read_to_string(root.join(rel))
            .unwrap_or_else(|err| panic!("read {rel}: {err}"));
        let stanza = package_stanza(&text, "agent_control_specification_core")
            .unwrap_or_else(|| panic!("{rel} is missing agent_control_specification_core"));
        assert_eq!(
            package_version(stanza),
            Some(SHIM_VERSION),
            "{rel} must lock the shim, not {COLLIDING_VERSION}"
        );
        assert!(
            stanza.contains("agent-control-spec"),
            "{rel} must record the path shim over agent-control-spec"
        );
        assert!(
            !stanza.contains("cedar-policy"),
            "{rel} still records the pre-retarget embedded engine graph"
        );
    }
}
