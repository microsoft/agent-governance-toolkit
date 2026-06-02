// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protocol-aware facet extraction for policy evaluation.
//!
//! Populates `sql.*` and `k8s.*` keys in the evaluation context so YAML
//! policy rules can reference wire-level semantics (e.g. `sql.verb`,
//! `k8s.namespace`) alongside HTTP metadata.
//!
//! This is the Rust port of `protocol_facets.py` and mirrors its public
//! contract: [`FacetRegistry`], [`default_registry`], and
//! [`extract_protocol_facets`].
//!
//! # Custom protocols
//!
//! ```
//! use agentmesh::protocol_facets::default_registry;
//! use serde_yaml::Value;
//!
//! default_registry().register("redis", |sub| {
//!     let mut out = std::collections::HashMap::new();
//!     if let Some(Value::String(cmd)) = sub.get("command") {
//!         out.insert("verb".to_string(), Value::String(cmd.to_uppercase()));
//!     }
//!     out
//! });
//! ```

use regex::Regex;
use serde_yaml::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Process-wide cache of compiled regexes. The set of patterns is fully
/// determined by the verb dispatch in [`pick_target`] / [`extract_tables`],
/// so the cache is bounded by a small constant and cannot grow unbounded.
fn cached_regex(pattern: &str) -> Arc<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Fast path: lock briefly to look up; compile outside the lock if absent
    // so a slow regex compile doesn't serialise other lookups behind us.
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = guard.get(pattern) {
            return Arc::clone(re);
        }
    }
    let compiled = Arc::new(Regex::new(pattern).expect("static pattern must compile"));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    // Another thread may have inserted in the meantime; prefer the existing.
    guard
        .entry(pattern.to_string())
        .or_insert_with(|| Arc::clone(&compiled))
        .clone()
}

/// Function signature for a protocol facet extractor.
///
/// Receives the sub-mapping stored at the registered context key and
/// returns the facet fields to merge back into that sub-mapping. The
/// returned keys are inserted as `<context_key>.<field>` flat entries on
/// the top-level context so they can be referenced by policy rules.
pub type ExtractorFn =
    Box<dyn Fn(&serde_yaml::Mapping) -> HashMap<String, Value> + Send + Sync + 'static>;

/// Holds protocol facet extractors keyed by context field name.
///
/// Each extractor receives the sub-mapping at its registered key and
/// returns fields to merge back. Errors inside an extractor are isolated:
/// because Rust functions cannot throw, extractors that cannot classify
/// input return UNKNOWN/empty values rather than propagating failure.
pub struct FacetRegistry {
    extractors: RwLock<Vec<(String, ExtractorFn)>>,
}

impl FacetRegistry {
    /// Create an empty registry with no built-in extractors.
    pub fn new() -> Self {
        Self {
            extractors: RwLock::new(Vec::new()),
        }
    }

    /// Register an extractor for sub-mappings stored at `context_key`.
    pub fn register<F>(&self, context_key: impl Into<String>, extractor: F)
    where
        F: Fn(&serde_yaml::Mapping) -> HashMap<String, Value> + Send + Sync + 'static,
    {
        let mut guard = self
            .extractors
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard.push((context_key.into(), Box::new(extractor)));
    }

    /// Number of registered extractors. Primarily for tests.
    pub fn len(&self) -> usize {
        self.extractors
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Returns true if no extractors are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all registered extractors. Primarily for tests.
    pub fn clear(&self) {
        self.extractors
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Run all registered extractors against `context` in place.
    ///
    /// For each registered key whose value is a mapping, the extractor is
    /// called and the returned fields are:
    /// 1. Merged back into the sub-mapping (so callers inspecting the raw
    ///    context see them), and
    /// 2. Inserted as flat `<key>.<field>` entries on the top-level
    ///    context so dot-keyed policy rules match.
    ///
    /// # Performance
    ///
    /// Each registered sub-mapping is `.clone()`d once so the extractor
    /// receives an owned snapshot without holding any borrow on `context`.
    /// For typical wire-protocol sub-maps (a handful of small string keys
    /// per protocol) this is sub-microsecond. Hot paths that need to push
    /// large structured payloads into the protocol context should keep
    /// them out of the sub-mapping (e.g. by stashing them at the top level
    /// where they bypass extractor cloning).
    pub fn extract(&self, context: &mut HashMap<String, Value>) {
        let extractors = self
            .extractors
            .read()
            .unwrap_or_else(|e| e.into_inner());

        // Snapshot the (key, facets) pairs first so we don't hold a mutable
        // borrow on `context` while iterating extractors.
        let mut updates: Vec<(String, HashMap<String, Value>)> = Vec::new();
        for (key, extractor) in extractors.iter() {
            let sub_map = match context.get(key) {
                Some(Value::Mapping(m)) => m.clone(),
                _ => continue,
            };
            // Per-extractor panic isolation: a buggy parser must never block
            // policy evaluation.
            let facets = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extractor(&sub_map)
            })) {
                Ok(facets) => facets,
                Err(_) => {
                    eprintln!(
                        "[protocol_facets] extractor for '{}' panicked; skipping",
                        key
                    );
                    continue;
                }
            };
            updates.push((key.clone(), facets));
        }

        for (key, facets) in updates {
            // Merge facets back into the sub-mapping so consumers can read
            // them via `context["sql"]["verb"]`.
            if let Some(Value::Mapping(m)) = context.get_mut(&key) {
                for (fk, fv) in &facets {
                    m.insert(Value::String(fk.clone()), fv.clone());
                }
            }
            // Also flatten to `key.field` at the top level so the existing
            // condition matcher (which is keyed by string) hits them
            // without needing dot-path traversal.
            for (fk, fv) in facets {
                context.insert(format!("{}.{}", key, fk), fv);
            }
        }
    }
}

impl Default for FacetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── SQL facets ──────────────────────────────────────────────────────────────

const SQL_KNOWN_VERBS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT",
    "REVOKE", "MERGE", "CALL", "EXECUTE", "EXPLAIN", "WITH", "REPLACE", "RENAME", "COMMENT",
];

fn known_verb(s: &str) -> bool {
    SQL_KNOWN_VERBS.contains(&s)
}

fn empty_sql_facets() -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert("verb".to_string(), Value::String(String::new()));
    m.insert("target".to_string(), Value::String(String::new()));
    m.insert("tables".to_string(), Value::String(String::new()));
    m.insert("functions".to_string(), Value::String(String::new()));
    m
}

fn unknown_sql_facets() -> HashMap<String, Value> {
    let mut m = empty_sql_facets();
    m.insert("verb".to_string(), Value::String("UNKNOWN".to_string()));
    m
}

/// Strip `/* ... */` and `-- ...` style SQL comments in a quote-aware way.
///
/// A naive regex strip would corrupt inputs like `SELECT '--'; DROP TABLE x`
/// (the `--` inside the string literal would be treated as a line comment
/// and the trailing `DROP` would be silently consumed). This walker
/// respects single, double and backtick quoting (with SQL doubled-quote
/// escapes) before recognising comment markers.
fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            out.push(ch);
            if ch == q {
                if chars.peek().copied() == Some(q) {
                    // Escaped doubled quote
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            quote = Some(ch);
            out.push(ch);
            continue;
        }
        // -- line comment
        if ch == '-' && chars.peek().copied() == Some('-') {
            chars.next(); // consume second '-'
            while let Some(&c) = chars.peek() {
                if c == '\n' || c == '\r' {
                    break;
                }
                chars.next();
            }
            out.push(' ');
            continue;
        }
        // /* block comment */
        if ch == '/' && chars.peek().copied() == Some('*') {
            chars.next(); // consume '*'
            let mut prev = '\0';
            for c in chars.by_ref() {
                if prev == '*' && c == '/' {
                    break;
                }
                prev = c;
            }
            out.push(' ');
            continue;
        }
        out.push(ch);
    }
    out
}

/// Split on top-level semicolons (outside quoted strings).
fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut quote: Option<char> = None;
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            buf.push(ch);
            if ch == q {
                // Escaped doubled quote
                if chars.peek().copied() == Some(q) {
                    if let Some(next) = chars.next() {
                        buf.push(next);
                    }
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            quote = Some(ch);
            buf.push(ch);
            continue;
        }
        if ch == ';' {
            let t = buf.trim().to_string();
            if !t.is_empty() {
                out.push(t);
            }
            buf.clear();
            continue;
        }
        buf.push(ch);
    }
    let tail = buf.trim().to_string();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// For a CTE-prefixed query, find the first DML keyword at top-level
/// paren depth. Falls back to SELECT.
fn detect_cte_inner_verb(query: &str) -> &'static str {
    let mut depth: i32 = 0;
    let mut quote: Option<char> = None;
    let mut token = String::new();
    let mut saw_with = false;
    let bytes: Vec<char> = query.chars().collect();
    for &ch in bytes.iter().chain(std::iter::once(&' ')) {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            quote = Some(ch);
            continue;
        }
        if ch == '(' {
            depth += 1;
            token.clear();
            continue;
        }
        if ch == ')' {
            depth = (depth - 1).max(0);
            token.clear();
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            token.push(ch);
            continue;
        }
        if !token.is_empty() {
            if depth == 0 {
                let up = token.to_ascii_uppercase();
                if !saw_with && up == "WITH" {
                    saw_with = true;
                } else {
                    match up.as_str() {
                        "SELECT" => return "SELECT",
                        "INSERT" => return "INSERT",
                        "UPDATE" => return "UPDATE",
                        "DELETE" => return "DELETE",
                        "MERGE" => return "MERGE",
                        _ => {}
                    }
                }
            }
            token.clear();
        }
    }
    "SELECT"
}

const IDENT_PART: &str = r#"(?:[A-Za-z_][A-Za-z0-9_]*|"[^"]+"|`[^`]+`|\[[^\]]+\])"#;

fn ident_pattern() -> String {
    format!(r"({0}(?:\.{0})*)", IDENT_PART)
}

/// Normalize an identifier capture: take last dotted segment and strip
/// surrounding quoting/brackets to match Python sqlglot `Table.name`.
fn normalize_ident(ident: &str) -> String {
    let s = ident.trim();
    let mut parts: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut depth: Option<char> = None;
    for ch in s.chars() {
        if let Some(open) = depth {
            buf.push(ch);
            let close = match open {
                '"' => '"',
                '`' => '`',
                '[' => ']',
                _ => '\0',
            };
            if ch == close {
                depth = None;
            }
            continue;
        }
        match ch {
            '"' | '`' | '[' => {
                depth = Some(ch);
                buf.push(ch);
            }
            '.' => {
                parts.push(std::mem::take(&mut buf));
            }
            _ => buf.push(ch),
        }
    }
    parts.push(buf);
    let mut last = parts.pop().unwrap_or_default().trim().to_string();
    if (last.starts_with('"') && last.ends_with('"'))
        || (last.starts_with('`') && last.ends_with('`'))
        || (last.starts_with('[') && last.ends_with(']'))
    {
        last = last[1..last.len() - 1].to_string();
    }
    last
}

fn extract_tables(query: &str, verb: &str) -> Vec<String> {
    let ident = ident_pattern();
    let mut patterns: Vec<Arc<Regex>> = Vec::new();
    patterns.push(cached_regex(&format!(r"(?i)\bFROM\s+{}", ident)));
    patterns.push(cached_regex(&format!(r"(?i)\bJOIN\s+{}", ident)));
    patterns.push(cached_regex(&format!(r"(?i)\bINTO\s+{}", ident)));
    patterns.push(cached_regex(&format!(r"(?i)\bUPDATE\s+{}", ident)));

    if matches!(verb, "DROP" | "TRUNCATE" | "ALTER" | "CREATE" | "RENAME") {
        let p = format!(
            r"(?i)\b{}\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?{}",
            verb, ident
        );
        patterns.push(cached_regex(&p));
        patterns.push(cached_regex(&format!(r"(?i)\bON\s+{}", ident)));
    }
    if matches!(verb, "GRANT" | "REVOKE") {
        patterns.push(cached_regex(&format!(r"(?i)\bON\s+(?:TABLE\s+)?{}", ident)));
    }

    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for re in &patterns {
        for caps in re.captures_iter(query) {
            if let Some(m) = caps.get(1) {
                let name = normalize_ident(m.as_str());
                if !name.is_empty() && seen.insert(name.clone()) {
                    found.push(name);
                }
            }
        }
    }
    found
}

const FUNC_DENYLIST: &[&str] = &[
    "VALUES", "IN", "EXISTS", "ANY", "ALL", "SOME", "CAST", "CASE", "IF", "DISTINCT", "ON",
    "USING", "WHEN", "THEN", "ELSE", "AND", "OR", "NOT",
];

fn extract_functions(query: &str) -> Vec<String> {
    static FUNC_RE: OnceLock<Regex> = OnceLock::new();
    let re = FUNC_RE.get_or_init(|| Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for caps in re.captures_iter(query) {
        if let Some(m) = caps.get(1) {
            let up = m.as_str().to_ascii_uppercase();
            if FUNC_DENYLIST.contains(&up.as_str()) {
                continue;
            }
            if seen.insert(up.clone()) {
                found.push(up);
            }
        }
    }
    found
}

fn pick_target(query: &str, verb: &str, tables: &[String]) -> String {
    let ident = ident_pattern();
    let pat = match verb {
        "INSERT" | "MERGE" => Some(format!(r"(?i)\bINTO\s+{}", ident)),
        "UPDATE" => Some(format!(r"(?i)\bUPDATE\s+{}", ident)),
        "DELETE" => Some(format!(r"(?i)\bDELETE\s+FROM\s+{}", ident)),
        "DROP" | "TRUNCATE" | "ALTER" | "CREATE" | "RENAME" => Some(format!(
            r"(?i)\b{}\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?{}",
            verb, ident
        )),
        "GRANT" | "REVOKE" => Some(format!(r"(?i)\bON\s+(?:TABLE\s+)?{}", ident)),
        _ => Some(format!(r"(?i)\bFROM\s+{}", ident)),
    };
    if let Some(p) = pat {
        let re = cached_regex(&p);
        if let Some(caps) = re.captures(query) {
            if let Some(m) = caps.get(1) {
                return normalize_ident(m.as_str());
            }
        }
    }
    // DELETE without FROM (rare dialects): fall back to first FROM
    if verb == "DELETE" {
        let re = cached_regex(&format!(r"(?i)\bFROM\s+{}", ident));
        if let Some(caps) = re.captures(query) {
            if let Some(m) = caps.get(1) {
                return normalize_ident(m.as_str());
            }
        }
    }
    tables.first().cloned().unwrap_or_default()
}

/// Built-in SQL facet extractor. Reads `sql_ctx["query"]` and returns
/// `{verb, target, tables, functions}` (as flat-string fields).
pub fn extract_sql_facets(sql_ctx: &serde_yaml::Mapping) -> HashMap<String, Value> {
    let raw = match sql_ctx.get(Value::String("query".to_string())) {
        Some(Value::String(s)) => s.clone(),
        _ => return empty_sql_facets(),
    };
    let stripped = strip_sql_comments(&raw);
    let trimmed = stripped.trim();
    if trimmed.is_empty() {
        return empty_sql_facets();
    }

    let statements = split_sql_statements(trimmed);
    if statements.len() > 1 {
        return unknown_sql_facets();
    }
    let query = statements.first().cloned().unwrap_or_else(|| trimmed.to_string());

    let verb_match = {
        static FIRST_WORD: OnceLock<Regex> = OnceLock::new();
        let re = FIRST_WORD.get_or_init(|| Regex::new(r"^\s*([A-Za-z]+)").unwrap());
        match re.captures(&query) {
            Some(c) => c.get(1).unwrap().as_str().to_ascii_uppercase(),
            None => return unknown_sql_facets(),
        }
    };

    let verb: String = if verb_match == "WITH" {
        detect_cte_inner_verb(&query).to_string()
    } else if known_verb(&verb_match) {
        verb_match
    } else {
        "UNKNOWN".to_string()
    };

    let tables = extract_tables(&query, &verb);
    let functions = extract_functions(&query);
    let target = pick_target(&query, &verb, &tables);

    let mut out = HashMap::new();
    out.insert("verb".to_string(), Value::String(verb));
    out.insert("target".to_string(), Value::String(target));
    out.insert("tables".to_string(), Value::String(tables.join(",")));
    out.insert("functions".to_string(), Value::String(functions.join(",")));
    out
}

// ── Kubernetes facets ───────────────────────────────────────────────────────

struct K8sPattern {
    re: Regex,
    groups: &'static [&'static str],
    is_watch: bool,
}

fn k8s_patterns() -> &'static Vec<K8sPattern> {
    static P: OnceLock<Vec<K8sPattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |p: &str, g: &'static [&'static str], is_watch: bool| K8sPattern {
            re: Regex::new(p).unwrap(),
            groups: g,
            is_watch,
        };
        vec![
            // Watch — namespaced collection
            mk(
                r"^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$",
                &["namespace", "resource"],
                true,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$",
                &["namespace", "resource"],
                true,
            ),
            // Watch — namespaced named
            mk(
                r"^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name"],
                true,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name"],
                true,
            ),
            // Watch — cluster
            mk(r"^/api/[^/]+/watch/([^/]+)/?$", &["resource"], true),
            mk(r"^/apis/[^/]+/[^/]+/watch/([^/]+)/?$", &["resource"], true),
            // Proxy tail
            mk(
                r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
                &["namespace", "resource", "name", "subresource"],
                false,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
                &["namespace", "resource", "name", "subresource"],
                false,
            ),
            // Generic — most specific first
            mk(
                r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name", "subresource"],
                false,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name", "subresource"],
                false,
            ),
            mk(
                r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name"],
                false,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
                &["namespace", "resource", "name"],
                false,
            ),
            mk(
                r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/?$",
                &["namespace", "resource"],
                false,
            ),
            mk(
                r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/?$",
                &["namespace", "resource"],
                false,
            ),
            mk(r"^/api/[^/]+/([^/]+)/([^/]+)/?$", &["resource", "name"], false),
            mk(r"^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/?$", &["resource", "name"], false),
            mk(r"^/api/[^/]+/([^/]+)/?$", &["resource"], false),
            mk(r"^/apis/[^/]+/[^/]+/([^/]+)/?$", &["resource"], false),
        ]
    })
}

fn method_to_verb_named(m: &str) -> Option<&'static str> {
    Some(match m {
        "GET" => "get",
        "DELETE" => "delete",
        "PUT" => "update",
        "PATCH" => "patch",
        "POST" => "create",
        "HEAD" => "get",
        _ => return None,
    })
}

fn method_to_verb_collection(m: &str) -> Option<&'static str> {
    Some(match m {
        "GET" => "list",
        "POST" => "create",
        "DELETE" => "deletecollection",
        "PUT" => "update",
        "PATCH" => "patch",
        "HEAD" => "list",
        _ => return None,
    })
}

/// Built-in Kubernetes facet extractor. Reads `k8s_ctx["method"]` and
/// `k8s_ctx["path"]` and returns `{verb, resource, namespace, name, subresource}`.
pub fn extract_k8s_facets(k8s_ctx: &serde_yaml::Mapping) -> HashMap<String, Value> {
    let method = match k8s_ctx.get(Value::String("method".to_string())) {
        Some(Value::String(s)) => s.to_ascii_uppercase(),
        _ => String::new(),
    };
    let raw_path = match k8s_ctx.get(Value::String("path".to_string())) {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };

    let mut out: HashMap<String, Value> = HashMap::new();
    for k in ["verb", "resource", "namespace", "name", "subresource"] {
        out.insert(k.to_string(), Value::String(String::new()));
    }
    if raw_path.is_empty() {
        return out;
    }

    // Strip query and fragment before path-pattern matching so resources
    // named "watch" cannot be spoofed and `?watch=true` can be detected
    // independently of the path.
    let (path_only, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_path.clone(), String::new()),
    };
    let path_only = match path_only.split_once('#') {
        Some((p, _)) => p.to_string(),
        None => path_only,
    };

    let mut matched: HashMap<&'static str, String> = HashMap::new();
    let mut matched_is_watch = false;
    for pat in k8s_patterns() {
        if let Some(caps) = pat.re.captures(&path_only) {
            for (i, g) in pat.groups.iter().enumerate() {
                if let Some(m) = caps.get(i + 1) {
                    matched.insert(*g, m.as_str().to_string());
                }
            }
            matched_is_watch = pat.is_watch;
            break;
        }
    }

    let resource = matched.get("resource").cloned().unwrap_or_default();
    let namespace = matched.get("namespace").cloned().unwrap_or_default();
    let name = matched.get("name").cloned().unwrap_or_default();
    let subresource = matched.get("subresource").cloned().unwrap_or_default();

    // Honor `?watch=true` query parameter as an alternate way to signal a
    // watch request. Only treat as watch when explicitly set to true/1.
    let query_signals_watch = query
        .split('&')
        .any(|kv| matches!(kv.split_once('='), Some(("watch", v)) if matches!(v, "true" | "1" | "True")));

    let is_watch = matched_is_watch || query_signals_watch;
    let verb: String = if is_watch {
        "watch".to_string()
    } else if !method.is_empty() {
        let tbl = if !name.is_empty() {
            method_to_verb_named(&method)
        } else {
            method_to_verb_collection(&method)
        };
        tbl.map(|s| s.to_string())
            .unwrap_or_else(|| method.to_ascii_lowercase())
    } else {
        String::new()
    };

    out.insert("verb".to_string(), Value::String(verb));
    out.insert("resource".to_string(), Value::String(resource));
    out.insert("namespace".to_string(), Value::String(namespace));
    out.insert("name".to_string(), Value::String(name));
    out.insert("subresource".to_string(), Value::String(subresource));
    out
}

// ── Default registry & top-level API ───────────────────────────────────────

/// Returns the process-wide default [`FacetRegistry`], pre-loaded with SQL
/// and Kubernetes extractors. Call `.register(..)` on it to add support
/// for new protocols.
pub fn default_registry() -> &'static FacetRegistry {
    static R: OnceLock<FacetRegistry> = OnceLock::new();
    R.get_or_init(|| {
        let r = FacetRegistry::new();
        r.register("sql", extract_sql_facets);
        r.register("k8s", extract_k8s_facets);
        r
    })
}

/// Enrich a policy evaluation context with wire-protocol facets.
///
/// Mutates `context` in place. Inserts flat `sql.verb`, `k8s.namespace`,
/// etc. keys so existing condition-matching code can match without
/// dot-path traversal.
pub fn extract_protocol_facets(context: &mut HashMap<String, Value>) {
    default_registry().extract(context);
}

/// Like [`extract_protocol_facets`] but using a caller-supplied registry.
///
/// Mirrors the Python `extract_protocol_facets(context, registry=...)` form
/// for callers that need an isolated or test-local registry rather than the
/// process-wide default.
pub fn extract_protocol_facets_with(
    context: &mut HashMap<String, Value>,
    registry: &FacetRegistry,
) {
    registry.extract(context);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(pairs: &[(&str, Value)]) -> serde_yaml::Mapping {
        let mut m = serde_yaml::Mapping::new();
        for (k, v) in pairs {
            m.insert(Value::String((*k).to_string()), v.clone());
        }
        m
    }

    // ── FacetRegistry ────────────────────────────────────────────────────

    #[test]
    fn registry_runs_custom_extractor_and_flattens_keys() {
        let r = FacetRegistry::new();
        r.register("redis", |sub| {
            let mut out = HashMap::new();
            let cmd = sub
                .get(Value::String("command".to_string()))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_uppercase();
            out.insert("verb".to_string(), Value::String(cmd));
            out
        });

        let mut ctx: HashMap<String, Value> = HashMap::new();
        ctx.insert(
            "redis".to_string(),
            Value::Mapping(map_of(&[(
                "command",
                Value::String("flushall".to_string()),
            )])),
        );

        r.extract(&mut ctx);

        // Flat key inserted at top level
        assert_eq!(
            ctx.get("redis.verb").and_then(|v| v.as_str()),
            Some("FLUSHALL")
        );
        // And merged into sub-mapping
        if let Some(Value::Mapping(m)) = ctx.get("redis") {
            assert_eq!(
                m.get(Value::String("verb".to_string()))
                    .and_then(|v| v.as_str()),
                Some("FLUSHALL")
            );
        } else {
            panic!("redis sub-context missing or not a mapping");
        }
    }

    #[test]
    fn registry_skips_missing_or_non_mapping_sub_contexts() {
        let r = FacetRegistry::new();
        r.register("sql", extract_sql_facets);

        let mut empty: HashMap<String, Value> = HashMap::new();
        r.extract(&mut empty);
        assert!(empty.is_empty());

        let mut wrong_type: HashMap<String, Value> = HashMap::new();
        wrong_type.insert("sql".to_string(), Value::String("not a mapping".into()));
        r.extract(&mut wrong_type);
        assert_eq!(wrong_type.len(), 1);
        assert!(!wrong_type.contains_key("sql.verb"));
    }

    #[test]
    fn registry_isolates_panicking_extractors() {
        let r = FacetRegistry::new();
        r.register("bad", |_| panic!("boom"));
        r.register("good", |_| {
            let mut m = HashMap::new();
            m.insert("ok".to_string(), Value::Bool(true));
            m
        });
        let mut ctx: HashMap<String, Value> = HashMap::new();
        ctx.insert("bad".to_string(), Value::Mapping(serde_yaml::Mapping::new()));
        ctx.insert(
            "good".to_string(),
            Value::Mapping(serde_yaml::Mapping::new()),
        );
        r.extract(&mut ctx);
        assert_eq!(ctx.get("good.ok"), Some(&Value::Bool(true)));
    }

    #[test]
    fn default_registry_has_sql_and_k8s() {
        let r = default_registry();
        assert!(r.len() >= 2);
    }

    // ── SQL ──────────────────────────────────────────────────────────────

    fn sql_facets(q: &str) -> HashMap<String, Value> {
        extract_sql_facets(&map_of(&[("query", Value::String(q.to_string()))]))
    }

    fn fv(m: &HashMap<String, Value>, k: &str) -> String {
        m.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    #[test]
    fn sql_empty_query_returns_empty_fields() {
        let f = extract_sql_facets(&serde_yaml::Mapping::new());
        assert_eq!(fv(&f, "verb"), "");
        let f = sql_facets("");
        assert_eq!(fv(&f, "verb"), "");
        let f = sql_facets("    ");
        assert_eq!(fv(&f, "verb"), "");
    }

    #[test]
    fn sql_basic_verbs_and_targets() {
        let cases = [
            ("SELECT * FROM users", "SELECT", "users"),
            ("select id from users", "SELECT", "users"),
            ("INSERT INTO orders (id) VALUES (1)", "INSERT", "orders"),
            (
                "UPDATE accounts SET balance = 0 WHERE id = 1",
                "UPDATE",
                "accounts",
            ),
            (
                "DELETE FROM sessions WHERE expired = true",
                "DELETE",
                "sessions",
            ),
            ("DROP TABLE production", "DROP", "production"),
            (
                "DROP TABLE IF EXISTS staging.payments",
                "DROP",
                "payments",
            ),
            ("TRUNCATE TABLE audit_log", "TRUNCATE", "audit_log"),
            (
                "ALTER TABLE users ADD COLUMN age INT",
                "ALTER",
                "users",
            ),
            ("CREATE TABLE foo (id INT)", "CREATE", "foo"),
            ("GRANT SELECT ON users TO bob", "GRANT", "users"),
            (
                "MERGE INTO dst USING src ON dst.id = src.id",
                "MERGE",
                "dst",
            ),
        ];
        for (q, verb, target) in cases {
            let f = sql_facets(q);
            assert_eq!(fv(&f, "verb"), verb, "query={}", q);
            assert_eq!(fv(&f, "target"), target, "query={}", q);
        }
    }

    #[test]
    fn sql_unknown_verb_for_garbage() {
        let f = sql_facets("WAT IS THIS");
        assert_eq!(fv(&f, "verb"), "UNKNOWN");
    }

    #[test]
    fn sql_multi_statement_fails_closed() {
        let f = sql_facets("SELECT 1; DROP TABLE production");
        assert_eq!(fv(&f, "verb"), "UNKNOWN");
        assert_eq!(fv(&f, "target"), "");
    }

    #[test]
    fn sql_trailing_semicolon_ok() {
        let f = sql_facets("SELECT * FROM users;");
        assert_eq!(fv(&f, "verb"), "SELECT");
        assert_eq!(fv(&f, "target"), "users");
    }

    #[test]
    fn sql_semicolon_in_string_is_not_boundary() {
        let f = sql_facets("SELECT * FROM users WHERE name = 'a;b'");
        assert_eq!(fv(&f, "verb"), "SELECT");
    }

    #[test]
    fn sql_cte_classifies_inner_verb() {
        assert_eq!(
            fv(
                &sql_facets(
                    "WITH stale AS (SELECT id FROM users WHERE inactive) DELETE FROM users WHERE id IN (SELECT id FROM stale)"
                ),
                "verb"
            ),
            "DELETE"
        );
        assert_eq!(
            fv(
                &sql_facets(
                    "WITH new_rows AS (SELECT 1 AS id) INSERT INTO audit (id) SELECT id FROM new_rows"
                ),
                "verb"
            ),
            "INSERT"
        );
        assert_eq!(
            fv(&sql_facets("WITH x AS (SELECT 1) SELECT * FROM x"), "verb"),
            "SELECT"
        );
    }

    #[test]
    fn sql_insert_target_is_written_object() {
        let f = sql_facets("INSERT INTO protected SELECT * FROM source");
        assert_eq!(fv(&f, "verb"), "INSERT");
        assert_eq!(fv(&f, "target"), "protected");
        let raw = fv(&f, "tables");
        let tables: Vec<&str> = raw.split(',').collect();
        assert!(tables.contains(&"protected"));
        assert!(tables.contains(&"source"));
    }

    #[test]
    fn sql_update_with_from_target_is_written_object() {
        let f = sql_facets(
            "UPDATE protected SET val = src.val FROM source AS src WHERE protected.id = src.id",
        );
        assert_eq!(fv(&f, "target"), "protected");
    }

    #[test]
    fn sql_delete_from_target() {
        let f = sql_facets("DELETE FROM protected WHERE id IN (SELECT id FROM staging)");
        assert_eq!(fv(&f, "verb"), "DELETE");
        assert_eq!(fv(&f, "target"), "protected");
    }

    #[test]
    fn sql_function_extraction_dedup_and_denylist() {
        let f = sql_facets("SELECT COUNT(id), Count(name), NOW() FROM users");
        let raw = fv(&f, "functions");
        let fns: Vec<&str> = raw.split(',').collect();
        assert!(fns.contains(&"COUNT"));
        assert!(fns.contains(&"NOW"));
        // dedupe
        assert_eq!(fns.iter().filter(|x| **x == "COUNT").count(), 1);

        let f = sql_facets("INSERT INTO t VALUES (CAST('1' AS INT))");
        let raw = fv(&f, "functions");
        let fns: Vec<&str> = raw.split(',').filter(|s| !s.is_empty()).collect();
        assert!(!fns.contains(&"VALUES"));
        assert!(!fns.contains(&"CAST"));
    }

    #[test]
    fn sql_strips_comments() {
        let f = sql_facets("/* hi */ -- comment\n SELECT id FROM users -- tail");
        assert_eq!(fv(&f, "verb"), "SELECT");
        assert_eq!(fv(&f, "target"), "users");
    }

    #[test]
    fn sql_strips_quoting() {
        let cases = [
            (r#"SELECT * FROM "public"."users""#, "users"),
            ("SELECT * FROM `db`.`orders`", "orders"),
            ("SELECT * FROM [dbo].[items]", "items"),
        ];
        for (q, expected) in cases {
            let f = sql_facets(q);
            let raw = fv(&f, "tables");
            let tables: Vec<&str> = raw.split(',').collect();
            assert!(tables.contains(&expected), "query={}, tables={:?}", q, tables);
        }
    }

    // ── K8s ──────────────────────────────────────────────────────────────

    fn k8s(method: &str, path: &str) -> HashMap<String, Value> {
        extract_k8s_facets(&map_of(&[
            ("method", Value::String(method.to_string())),
            ("path", Value::String(path.to_string())),
        ]))
    }

    #[test]
    fn k8s_empty_path() {
        let f = extract_k8s_facets(&serde_yaml::Mapping::new());
        assert_eq!(fv(&f, "verb"), "");
        assert_eq!(fv(&f, "resource"), "");
    }

    #[test]
    fn k8s_cluster_list() {
        let f = k8s("GET", "/api/v1/nodes");
        assert_eq!(fv(&f, "verb"), "list");
        assert_eq!(fv(&f, "resource"), "nodes");
        assert_eq!(fv(&f, "namespace"), "");
    }

    #[test]
    fn k8s_namespaced_collection_list() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods");
        assert_eq!(fv(&f, "verb"), "list");
        assert_eq!(fv(&f, "namespace"), "prod");
        assert_eq!(fv(&f, "resource"), "pods");
        assert_eq!(fv(&f, "name"), "");
    }

    #[test]
    fn k8s_named_object_get() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods/mypod");
        assert_eq!(fv(&f, "verb"), "get");
        assert_eq!(fv(&f, "name"), "mypod");
    }

    #[test]
    fn k8s_exec_subresource() {
        let f = k8s("POST", "/api/v1/namespaces/prod/pods/mypod/exec");
        assert_eq!(fv(&f, "subresource"), "exec");
        assert_eq!(fv(&f, "verb"), "create");
    }

    #[test]
    fn k8s_delete_collection_vs_named() {
        let coll = k8s("DELETE", "/api/v1/namespaces/prod/pods");
        assert_eq!(fv(&coll, "verb"), "deletecollection");

        let named = k8s("DELETE", "/api/v1/namespaces/prod/pods/p1");
        assert_eq!(fv(&named, "verb"), "delete");
    }

    #[test]
    fn k8s_apis_group() {
        let f = k8s("GET", "/apis/apps/v1/namespaces/prod/deployments/web");
        assert_eq!(fv(&f, "resource"), "deployments");
        assert_eq!(fv(&f, "name"), "web");
        assert_eq!(fv(&f, "namespace"), "prod");
        assert_eq!(fv(&f, "verb"), "get");
    }

    #[test]
    fn k8s_trailing_slash() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods/");
        assert_eq!(fv(&f, "resource"), "pods");
        assert_eq!(fv(&f, "namespace"), "prod");
    }

    #[test]
    fn k8s_unknown_method_lowercased() {
        let f = k8s("OPTIONS", "/api/v1/namespaces/prod/pods");
        assert_eq!(fv(&f, "verb"), "options");
    }

    #[test]
    fn k8s_missing_method_yields_empty_verb() {
        let f = extract_k8s_facets(&map_of(&[(
            "path",
            Value::String("/api/v1/namespaces/prod/pods".to_string()),
        )]));
        assert_eq!(fv(&f, "verb"), "");
        assert_eq!(fv(&f, "resource"), "pods");
    }

    #[test]
    fn k8s_watch_paths() {
        let f = k8s("GET", "/api/v1/watch/pods");
        assert_eq!(fv(&f, "verb"), "watch");
        assert_eq!(fv(&f, "resource"), "pods");

        let f = k8s("GET", "/api/v1/watch/namespaces/prod/pods");
        assert_eq!(fv(&f, "verb"), "watch");
        assert_eq!(fv(&f, "namespace"), "prod");

        let f = k8s("GET", "/api/v1/watch/namespaces/prod/pods/web");
        assert_eq!(fv(&f, "verb"), "watch");
        assert_eq!(fv(&f, "name"), "web");
    }

    #[test]
    fn k8s_proxy_tail() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods/web/proxy/healthz");
        assert_eq!(fv(&f, "subresource"), "proxy");
        assert_eq!(fv(&f, "name"), "web");
        assert_eq!(fv(&f, "resource"), "pods");
    }

    #[test]
    fn k8s_log_and_status_subresources() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods/web/log");
        assert_eq!(fv(&f, "subresource"), "log");

        let f = k8s("PATCH", "/apis/apps/v1/namespaces/prod/deployments/web/status");
        assert_eq!(fv(&f, "subresource"), "status");
        assert_eq!(fv(&f, "verb"), "patch");
    }

    // ── extract_protocol_facets default flow ─────────────────────────────

    #[test]
    fn default_extract_flattens_sql_into_context() {
        let mut ctx: HashMap<String, Value> = HashMap::new();
        ctx.insert(
            "sql".to_string(),
            Value::Mapping(map_of(&[(
                "query",
                Value::String("DROP TABLE production".to_string()),
            )])),
        );
        extract_protocol_facets(&mut ctx);
        assert_eq!(
            ctx.get("sql.verb").and_then(|v| v.as_str()),
            Some("DROP")
        );
        assert_eq!(
            ctx.get("sql.target").and_then(|v| v.as_str()),
            Some("production")
        );
    }

    #[test]
    fn default_extract_flattens_k8s_into_context() {
        let mut ctx: HashMap<String, Value> = HashMap::new();
        ctx.insert(
            "k8s".to_string(),
            Value::Mapping(map_of(&[
                ("method", Value::String("DELETE".to_string())),
                (
                    "path",
                    Value::String("/api/v1/namespaces/prod/pods/p1".to_string()),
                ),
            ])),
        );
        extract_protocol_facets(&mut ctx);
        assert_eq!(
            ctx.get("k8s.verb").and_then(|v| v.as_str()),
            Some("delete")
        );
        assert_eq!(
            ctx.get("k8s.namespace").and_then(|v| v.as_str()),
            Some("prod")
        );
    }

    // ── Regression: comment-stripping must be quote-aware ────────────────

    #[test]
    fn sql_double_dash_inside_string_literal_does_not_hide_injection() {
        // Naive `--[^\n\r]*` regex stripping would eat from `--';` through
        // to end-of-line and silently turn this into a single SELECT. The
        // quote-aware stripper preserves the semicolon so the multi-
        // statement guard fires.
        let f = sql_facets("SELECT '--'; DROP TABLE production");
        assert_eq!(fv(&f, "verb"), "UNKNOWN");
    }

    #[test]
    fn sql_block_comment_inside_string_literal_preserved() {
        let f = sql_facets("SELECT '/* not a comment */' FROM users");
        assert_eq!(fv(&f, "verb"), "SELECT");
        assert_eq!(fv(&f, "target"), "users");
    }

    // ── Regression: K8s query-string / fragment / spoofed names ──────────

    #[test]
    fn k8s_query_string_is_stripped_before_path_match() {
        // Resource `pods` must still parse with a trailing ?fieldManager=...
        let f = k8s("GET", "/api/v1/namespaces/prod/pods?fieldManager=test");
        assert_eq!(fv(&f, "resource"), "pods");
        assert_eq!(fv(&f, "namespace"), "prod");
        assert_eq!(fv(&f, "verb"), "list");
    }

    #[test]
    fn k8s_watch_query_param_signals_watch_verb() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods?watch=true");
        assert_eq!(fv(&f, "verb"), "watch");
        assert_eq!(fv(&f, "resource"), "pods");
    }

    #[test]
    fn k8s_resource_named_watch_does_not_falsely_trigger_watch_verb() {
        // Namespace name `watch-test` contains the substring `/watch` after
        // /namespaces/ — the previous `path.contains("/watch/")` substring
        // check would have spuriously emitted verb=watch.
        let f = k8s("GET", "/api/v1/namespaces/watch-test/pods");
        assert_eq!(fv(&f, "verb"), "list");
        assert_eq!(fv(&f, "namespace"), "watch-test");
    }

    #[test]
    fn k8s_fragment_is_stripped() {
        let f = k8s("GET", "/api/v1/namespaces/prod/pods#anchor");
        assert_eq!(fv(&f, "resource"), "pods");
    }

    // ── extract_protocol_facets_with custom registry ─────────────────────

    #[test]
    fn extract_with_custom_registry_does_not_touch_default() {
        let r = FacetRegistry::new();
        r.register("sql", |_| {
            let mut m = HashMap::new();
            m.insert("verb".to_string(), Value::String("CUSTOM".to_string()));
            m
        });
        let mut ctx: HashMap<String, Value> = HashMap::new();
        ctx.insert(
            "sql".to_string(),
            Value::Mapping(map_of(&[(
                "query",
                Value::String("SELECT 1".to_string()),
            )])),
        );
        extract_protocol_facets_with(&mut ctx, &r);
        assert_eq!(
            ctx.get("sql.verb").and_then(|v| v.as_str()),
            Some("CUSTOM")
        );
    }
}
