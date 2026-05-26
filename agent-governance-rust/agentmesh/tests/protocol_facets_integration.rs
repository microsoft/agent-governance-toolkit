// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Integration tests for wire-protocol-aware policy evaluation.

use agentmesh::PolicyEngine;
use serde_yaml::Value;
use std::collections::HashMap;

fn ctx_with_sql(query: &str) -> HashMap<String, Value> {
    let mut sub = serde_yaml::Mapping::new();
    sub.insert(Value::String("query".into()), Value::String(query.into()));
    let mut ctx = HashMap::new();
    ctx.insert("sql".to_string(), Value::Mapping(sub));
    ctx
}

fn ctx_with_k8s(method: &str, path: &str) -> HashMap<String, Value> {
    let mut sub = serde_yaml::Mapping::new();
    sub.insert(Value::String("method".into()), Value::String(method.into()));
    sub.insert(Value::String("path".into()), Value::String(path.into()));
    let mut ctx = HashMap::new();
    ctx.insert("k8s".to_string(), Value::Mapping(sub));
    ctx
}

#[test]
fn denies_destructive_sql_via_sql_verb_list() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-destructive-sql
    type: capability
    denied_actions: ["*"]
    conditions:
      sql.verb: [DROP, TRUNCATE, DELETE]
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate("db.exec", Some(&ctx_with_sql("DROP TABLE production")));
    assert!(
        matches!(decision, agentmesh::PolicyDecision::Deny(_)),
        "expected deny, got {:?}",
        decision
    );
}

#[test]
fn allows_select_when_not_in_destructive_set() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-destructive-sql
    type: capability
    denied_actions: ["*"]
    conditions:
      sql.verb: [DROP, TRUNCATE, DELETE]
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate("db.exec", Some(&ctx_with_sql("SELECT * FROM users")));
    assert!(
        matches!(decision, agentmesh::PolicyDecision::Allow),
        "expected allow, got {:?}",
        decision
    );
}

#[test]
fn denies_pod_exec_via_k8s_subresource() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-k8s-exec
    type: capability
    denied_actions: ["*"]
    conditions:
      k8s.subresource: exec
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate(
        "k8s.request",
        Some(&ctx_with_k8s("POST", "/api/v1/namespaces/prod/pods/web/exec")),
    );
    assert!(
        matches!(decision, agentmesh::PolicyDecision::Deny(_)),
        "expected deny, got {:?}",
        decision
    );
}

#[test]
fn denies_production_namespace_writes() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-k8s-prod
    type: capability
    denied_actions: ["*"]
    conditions:
      k8s.namespace: production
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate(
        "k8s.request",
        Some(&ctx_with_k8s("DELETE", "/api/v1/namespaces/production/pods/web")),
    );
    assert!(matches!(
        decision,
        agentmesh::PolicyDecision::Deny(_)
    ));
}

#[test]
fn sql_target_can_be_referenced_directly() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies:
  - name: deny-writes-to-protected
    type: capability
    denied_actions: ["*"]
    conditions:
      sql.target: protected
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate(
        "db.exec",
        Some(&ctx_with_sql("INSERT INTO protected SELECT * FROM staging")),
    );
    assert!(matches!(
        decision,
        agentmesh::PolicyDecision::Deny(_)
    ));
}

#[test]
fn empty_context_does_not_break_evaluation() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies: []
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let decision = engine.evaluate("anything", None);
    assert!(matches!(
        decision,
        agentmesh::PolicyDecision::Allow
    ));
}

#[test]
fn caller_context_is_not_mutated_by_evaluation() {
    let yaml = r#"
version: "1"
agent: "did:example:agent1"
policies: []
"#;
    let engine = PolicyEngine::new();
    engine.load_from_yaml(yaml).expect("load");
    let ctx = ctx_with_sql("SELECT 1");
    let snapshot = ctx.clone();
    let _ = engine.evaluate("x", Some(&ctx));
    assert_eq!(ctx, snapshot, "PolicyEngine.evaluate must not mutate caller context");
}

