// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared cache for runtime-compiled regex patterns.
//!
//! Several governance evaluation paths compile a `Regex` from a string
//! that comes from deserialized config (policy conditions, governance
//! patterns). Each evaluation previously re-parsed the same pattern,
//! turning every policy check into a regex-compile workload.
//!
//! [`compiled_regex`] caches by pattern string: each unique pattern is
//! parsed once, then served from a `HashMap` for subsequent callers.
//! The compile step happens outside the cache lock so a slow parse
//! doesn't block readers looking up other patterns.

use regex::Regex;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

fn cache() -> &'static Mutex<HashMap<String, Arc<Regex>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Regex>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Return the compiled form of `pattern`, parsing it on first use and
/// reusing the cached value on subsequent calls. Returns `None` if the
/// pattern fails to compile; the failure is not cached, so a later
/// caller with a corrected pattern is unaffected.
pub(crate) fn compiled_regex(pattern: &str) -> Option<Arc<Regex>> {
    {
        let guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = guard.get(pattern) {
            return Some(Arc::clone(re));
        }
    }

    // Compile outside the lock — regex parsing can be non-trivial and
    // we don't want to block other lookups while it runs.
    let compiled = Arc::new(Regex::new(pattern).ok()?);

    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    Some(Arc::clone(
        guard.entry(pattern.to_string()).or_insert(compiled),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_same_compiled_regex_across_calls() {
        let first = compiled_regex(r"^foo\d+$").unwrap();
        let second = compiled_regex(r"^foo\d+$").unwrap();
        // Both arcs point to the same compiled Regex.
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn caches_distinct_patterns_independently() {
        let a = compiled_regex(r"^a+$").unwrap();
        let b = compiled_regex(r"^b+$").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(a.is_match("aaaa"));
        assert!(b.is_match("bbbb"));
        assert!(!a.is_match("bbbb"));
    }

    #[test]
    fn invalid_pattern_returns_none_without_caching() {
        assert!(compiled_regex(r"(unclosed").is_none());
        // A valid pattern still works after a prior failure.
        assert!(compiled_regex(r"^x$").is_some());
    }
}
