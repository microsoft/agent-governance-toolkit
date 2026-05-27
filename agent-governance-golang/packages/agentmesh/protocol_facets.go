// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package agentmesh — protocol-aware facet extraction for policy evaluation.
//
// Populates sql.* and k8s.* fields in the policy evaluation context so rules
// can reference wire-level semantics (e.g. sql.verb, k8s.namespace) alongside
// HTTP metadata. This is the Go port of protocol_facets.py and mirrors its
// public contract: FacetRegistry, DefaultRegistry, ExtractProtocolFacets.
//
// Add support for a new protocol via DefaultRegistry().Register:
//
//	DefaultRegistry().Register("redis", func(sub map[string]any) map[string]any {
//	    cmd, _ := sub["command"].(string)
//	    return map[string]any{"verb": strings.ToUpper(cmd)}
//	})

package agentmesh

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// FacetExtractor receives the sub-map stored at its registered context key
// and returns the facet fields to merge back into that sub-map and to
// expose as flat `<key>.<field>` entries on the top-level context.
type FacetExtractor func(sub map[string]any) map[string]any

// FacetRegistry holds protocol facet extractors keyed by context field name.
// Errors thrown inside an extractor are caught (via recover) and logged so a
// broken parser can never block policy evaluation.
type FacetRegistry struct {
	mu         sync.RWMutex
	extractors []registeredExtractor
}

type registeredExtractor struct {
	key string
	fn  FacetExtractor
}

// NewFacetRegistry returns an empty registry with no built-in extractors.
func NewFacetRegistry() *FacetRegistry {
	return &FacetRegistry{}
}

// Register adds an extractor for sub-maps stored at contextKey.
func (r *FacetRegistry) Register(contextKey string, fn FacetExtractor) {
	if contextKey == "" || fn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extractors = append(r.extractors, registeredExtractor{key: contextKey, fn: fn})
}

// Len returns the number of registered extractors. Primarily for tests.
func (r *FacetRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.extractors)
}

// Clear removes all registered extractors. Primarily for tests.
func (r *FacetRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.extractors = nil
}

// Extract runs all registered extractors against context in place. For each
// registered key whose value is a map[string]any, the extractor is called and
// the returned fields are:
//
//  1. Merged back into a fresh copy of the sub-map (which replaces the
//     original slot, so caller-side aliases are not mutated), and
//  2. Flattened to `<key>.<field>` top-level entries so the existing
//     condition matcher (which is keyed by string) can resolve them
//     without dot-path traversal.
//
// Snapshot-then-invoke pattern avoids holding the registry lock while
// arbitrary extractor code runs (no deadlock if an extractor calls
// Register from within itself).
func (r *FacetRegistry) Extract(context map[string]any) {
	if context == nil {
		return
	}
	r.mu.RLock()
	snapshot := make([]registeredExtractor, len(r.extractors))
	copy(snapshot, r.extractors)
	r.mu.RUnlock()

	for _, ex := range snapshot {
		raw, ok := context[ex.key]
		if !ok || raw == nil {
			continue
		}
		sub, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		facets := runExtractor(ex.key, ex.fn, sub)
		if facets == nil {
			continue
		}
		// Replace slot with a merged copy so we don't mutate the caller's map.
		merged := make(map[string]any, len(sub)+len(facets))
		for k, v := range sub {
			merged[k] = v
		}
		for k, v := range facets {
			merged[k] = v
		}
		context[ex.key] = merged
		for k, v := range facets {
			context[ex.key+"."+k] = v
		}
	}
}

func runExtractor(key string, fn FacetExtractor, sub map[string]any) (out map[string]any) {
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "[protocol-facets] extractor for %q panicked: %v\n", key, rec)
			out = nil
		}
	}()
	// Hand the extractor a defensive copy so a buggy implementation cannot
	// mutate the caller's input.
	copied := make(map[string]any, len(sub))
	for k, v := range sub {
		copied[k] = v
	}
	return fn(copied)
}

var (
	defaultRegistryOnce sync.Once
	defaultRegistry     *FacetRegistry
)

// DefaultRegistry returns the process-wide default registry, pre-loaded with
// SQL and Kubernetes extractors. Call Register on it to add support for
// new protocols.
func DefaultRegistry() *FacetRegistry {
	defaultRegistryOnce.Do(func() {
		defaultRegistry = NewFacetRegistry()
		defaultRegistry.Register("sql", ExtractSQLFacets)
		defaultRegistry.Register("k8s", ExtractK8sFacets)
	})
	return defaultRegistry
}

// ExtractProtocolFacets enriches a policy evaluation context with wire-
// protocol facets using DefaultRegistry. Mutates context in place.
func ExtractProtocolFacets(context map[string]any) {
	DefaultRegistry().Extract(context)
}

// ExtractProtocolFacetsWith is the same as ExtractProtocolFacets but accepts
// a caller-supplied registry. Mirrors the Python
// extract_protocol_facets(context, registry=...) overload.
func ExtractProtocolFacetsWith(context map[string]any, registry *FacetRegistry) {
	if registry == nil {
		return
	}
	registry.Extract(context)
}

// ── SQL ──────────────────────────────────────────────────────────────────────

var sqlKnownVerbs = map[string]struct{}{
	"SELECT": {}, "INSERT": {}, "UPDATE": {}, "DELETE": {}, "DROP": {},
	"TRUNCATE": {}, "ALTER": {}, "CREATE": {}, "GRANT": {}, "REVOKE": {},
	"MERGE": {}, "CALL": {}, "EXECUTE": {}, "EXPLAIN": {}, "WITH": {},
	"REPLACE": {}, "RENAME": {}, "COMMENT": {},
}

var sqlFunctionDenylist = map[string]struct{}{
	"VALUES": {}, "IN": {}, "EXISTS": {}, "ANY": {}, "ALL": {}, "SOME": {},
	"CAST": {}, "CASE": {}, "IF": {}, "DISTINCT": {}, "ON": {}, "USING": {},
	"WHEN": {}, "THEN": {}, "ELSE": {}, "AND": {}, "OR": {}, "NOT": {},
}

const identPart = `(?:[A-Za-z_][A-Za-z0-9_]*|"[^"]+"|` + "`[^`]+`" + `|\[[^\]]+\])`

var (
	identPattern  = `(` + identPart + `(?:\.` + identPart + `)*)`
	sqlFirstWord  = regexp.MustCompile(`^\s*([A-Za-z]+)`)
	funcCallRe    = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	reCache       sync.Map // pattern string -> *regexp.Regexp
)

func reCompile(pat string) *regexp.Regexp {
	if v, ok := reCache.Load(pat); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(?i)` + pat)
	reCache.Store(pat, re)
	return re
}

func emptySQL() map[string]any {
	return map[string]any{"verb": "", "target": "", "tables": "", "functions": ""}
}

func unknownSQL() map[string]any {
	m := emptySQL()
	m["verb"] = "UNKNOWN"
	return m
}

// ExtractSQLFacets is the built-in SQL extractor. Reads sub["query"] and
// returns {verb, target, tables, functions} as flat strings.
func ExtractSQLFacets(sub map[string]any) map[string]any {
	raw, _ := sub["query"].(string)
	if strings.TrimSpace(raw) == "" {
		return emptySQL()
	}
	stripped := stripSQLComments(raw)
	stripped = strings.TrimSpace(stripped)
	if stripped == "" {
		return emptySQL()
	}

	statements := splitSQLStatements(stripped)
	if len(statements) > 1 {
		return unknownSQL()
	}
	query := stripped
	if len(statements) == 1 {
		query = statements[0]
	}

	first := sqlFirstWord.FindStringSubmatch(query)
	if first == nil {
		return unknownSQL()
	}
	surface := strings.ToUpper(first[1])

	var verb string
	if surface == "WITH" {
		verb = detectCTEInnerVerb(query)
	} else if _, ok := sqlKnownVerbs[surface]; ok {
		verb = surface
	} else {
		verb = "UNKNOWN"
	}

	tables := extractTables(query, verb)
	functions := extractFunctions(query)
	target := pickTarget(query, verb, tables)

	return map[string]any{
		"verb":      verb,
		"target":    target,
		"tables":    strings.Join(tables, ","),
		"functions": strings.Join(functions, ","),
	}
}

// stripSQLComments is a quote-aware comment stripper. A naive regex strip
// would corrupt input like SELECT '--'; DROP TABLE x by treating the
// in-string -- as a line comment and consuming the rest of the input.
func stripSQLComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	runes := []rune(sql)
	var quote rune
	i := 0
	for i < len(runes) {
		c := runes[i]
		if quote != 0 {
			b.WriteRune(c)
			if c == quote {
				if i+1 < len(runes) && runes[i+1] == quote {
					b.WriteRune(runes[i+1])
					i += 2
					continue
				}
				quote = 0
			}
			i++
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			b.WriteRune(c)
			i++
			continue
		}
		if c == '-' && i+1 < len(runes) && runes[i+1] == '-' {
			i += 2
			for i < len(runes) && runes[i] != '\n' && runes[i] != '\r' {
				i++
			}
			b.WriteByte(' ')
			continue
		}
		if c == '/' && i+1 < len(runes) && runes[i+1] == '*' {
			i += 2
			for i+1 < len(runes) && !(runes[i] == '*' && runes[i+1] == '/') {
				i++
			}
			if i+1 < len(runes) {
				i += 2
			}
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(c)
		i++
	}
	return b.String()
}

func splitSQLStatements(sql string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if quote != 0 {
			b.WriteRune(c)
			if c == quote {
				if i+1 < len(runes) && runes[i+1] == quote {
					b.WriteRune(runes[i+1])
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			b.WriteRune(c)
			continue
		}
		if c == ';' {
			t := strings.TrimSpace(b.String())
			if t != "" {
				out = append(out, t)
			}
			b.Reset()
			continue
		}
		b.WriteRune(c)
	}
	tail := strings.TrimSpace(b.String())
	if tail != "" {
		out = append(out, tail)
	}
	return out
}

// detectCTEInnerVerb finds the first DML keyword at top-level paren depth in
// a WITH-prefixed query. Falls back to SELECT.
func detectCTEInnerVerb(query string) string {
	depth := 0
	var quote rune
	var token strings.Builder
	sawWith := false
	// Iterate over runes (not bytes) so multi-byte UTF-8 sequences in
	// identifiers or string literals can't be misinterpreted mid-rune.
	runes := []rune(query)
	for i := 0; i <= len(runes); i++ {
		var c rune
		if i < len(runes) {
			c = runes[i]
		} else {
			c = ' '
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
			token.Reset()
			continue
		}
		if c == ')' {
			if depth > 0 {
				depth--
			}
			token.Reset()
			continue
		}
		if unicode.IsLetter(c) || c == '_' {
			token.WriteRune(c)
			continue
		}
		if token.Len() > 0 {
			if depth == 0 {
				up := strings.ToUpper(token.String())
				if !sawWith && up == "WITH" {
					sawWith = true
				} else {
					switch up {
					case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE":
						return up
					}
				}
			}
			token.Reset()
		}
	}
	return "SELECT"
}

func extractTables(query string, verb string) []string {
	patterns := []string{
		`\bFROM\s+` + identPattern,
		`\bJOIN\s+` + identPattern,
		`\bINTO\s+` + identPattern,
		`\bUPDATE\s+` + identPattern,
	}
	switch verb {
	case "DROP", "TRUNCATE", "ALTER", "CREATE", "RENAME":
		patterns = append(patterns,
			`\b`+verb+`\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?`+identPattern,
			`\bON\s+`+identPattern)
	case "GRANT", "REVOKE":
		patterns = append(patterns, `\bON\s+(?:TABLE\s+)?`+identPattern)
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range patterns {
		for _, m := range reCompile(p).FindAllStringSubmatch(query, -1) {
			name := normalizeIdent(m[1])
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

func extractFunctions(query string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range funcCallRe.FindAllStringSubmatch(query, -1) {
		up := strings.ToUpper(m[1])
		if _, deny := sqlFunctionDenylist[up]; deny {
			continue
		}
		if _, ok := seen[up]; ok {
			continue
		}
		seen[up] = struct{}{}
		out = append(out, up)
	}
	return out
}

func pickTarget(query, verb string, tables []string) string {
	// Optional modifier keywords that can appear between the verb and the
	// target table in common SQL dialects:
	//   INSERT [OR REPLACE | OR IGNORE | IGNORE] [INTO] <t>
	//   UPDATE [ONLY] <t>
	//   DELETE FROM [ONLY] <t>
	//   CREATE [OR REPLACE] [TABLE|VIEW|...] <t>
	const insertMods = `(?:OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK)\s+|IGNORE\s+)?`
	const createMods = `(?:OR\s+REPLACE\s+)?`
	const onlyMod = `(?:ONLY\s+)?`

	var pat string
	switch verb {
	case "INSERT":
		pat = `\bINSERT\s+` + insertMods + `(?:INTO\s+)?` + identPattern
	case "MERGE":
		pat = `\bINTO\s+` + identPattern
	case "UPDATE":
		pat = `\bUPDATE\s+` + onlyMod + identPattern
	case "DELETE":
		pat = `\bDELETE\s+FROM\s+` + onlyMod + identPattern
	case "DROP", "TRUNCATE", "ALTER", "RENAME":
		pat = `\b` + verb + `\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?` + identPattern
	case "CREATE":
		pat = `\bCREATE\s+` + createMods + `(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?` + identPattern
	case "GRANT", "REVOKE":
		pat = `\bON\s+(?:TABLE\s+)?` + identPattern
	default:
		pat = `\bFROM\s+` + identPattern
	}
	if m := reCompile(pat).FindStringSubmatch(query); m != nil {
		return normalizeIdent(m[1])
	}
	if verb == "DELETE" {
		if m := reCompile(`\bFROM\s+` + onlyMod + identPattern).FindStringSubmatch(query); m != nil {
			return normalizeIdent(m[1])
		}
	}
	if len(tables) > 0 {
		return tables[0]
	}
	return ""
}

// normalizeIdent takes the last dotted segment of an identifier and strips
// surrounding quotes/brackets, mirroring Python sqlglot Table.name.
func normalizeIdent(ident string) string {
	s := strings.TrimSpace(ident)
	var parts []string
	var b strings.Builder
	var depth rune
	for _, ch := range s {
		if depth != 0 {
			b.WriteRune(ch)
			var close rune
			switch depth {
			case '"':
				close = '"'
			case '`':
				close = '`'
			case '[':
				close = ']'
			}
			if ch == close {
				depth = 0
			}
			continue
		}
		switch ch {
		case '"', '`', '[':
			depth = ch
			b.WriteRune(ch)
		case '.':
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(ch)
		}
	}
	parts = append(parts, b.String())
	last := strings.TrimSpace(parts[len(parts)-1])
	if (strings.HasPrefix(last, `"`) && strings.HasSuffix(last, `"`)) ||
		(strings.HasPrefix(last, "`") && strings.HasSuffix(last, "`")) ||
		(strings.HasPrefix(last, "[") && strings.HasSuffix(last, "]")) {
		if len(last) >= 2 {
			last = last[1 : len(last)-1]
		}
	}
	return last
}

// Note: helper `reCompile` panics if the pattern is invalid. All patterns in
// this file are package-level constants, so misuse would surface at startup
// in tests rather than at runtime.

// ── Kubernetes ───────────────────────────────────────────────────────────────

var methodToVerbNamed = map[string]string{
	"GET": "get", "DELETE": "delete", "PUT": "update",
	"PATCH": "patch", "POST": "create", "HEAD": "get",
}

var methodToVerbCollection = map[string]string{
	"GET": "list", "POST": "create", "DELETE": "deletecollection",
	"PUT": "update", "PATCH": "patch", "HEAD": "list",
}

type k8sPattern struct {
	re      *regexp.Regexp
	groups  []string
	isWatch bool
}

var k8sPatterns = []k8sPattern{
	// Watch — namespaced collection
	{regexp.MustCompile(`^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource"}, true},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource"}, true},
	// Watch — namespaced named
	{regexp.MustCompile(`^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name"}, true},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name"}, true},
	// Watch — cluster
	{regexp.MustCompile(`^/api/[^/]+/watch/([^/]+)/?$`), []string{"resource"}, true},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/watch/([^/]+)/?$`), []string{"resource"}, true},
	// Proxy tail — namespaced
	{regexp.MustCompile(`^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$`), []string{"namespace", "resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$`), []string{"namespace", "resource", "name", "subresource"}, false},
	// Generic namespaced — most specific first
	{regexp.MustCompile(`^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource", "name"}, false},
	{regexp.MustCompile(`^/api/[^/]+/namespaces/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/?$`), []string{"namespace", "resource"}, false},
	// Cluster-scoped subresource (e.g. /api/v1/nodes/n1/status, /apis/.../crds/foo/status)
	{regexp.MustCompile(`^/api/[^/]+/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/([^/]+)/?$`), []string{"resource", "name", "subresource"}, false},
	// Cluster-scoped proxy tail
	{regexp.MustCompile(`^/api/[^/]+/([^/]+)/([^/]+)/(proxy)(?:/.*)?$`), []string{"resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/(proxy)(?:/.*)?$`), []string{"resource", "name", "subresource"}, false},
	{regexp.MustCompile(`^/api/[^/]+/([^/]+)/([^/]+)/?$`), []string{"resource", "name"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/?$`), []string{"resource", "name"}, false},
	{regexp.MustCompile(`^/api/[^/]+/([^/]+)/?$`), []string{"resource"}, false},
	{regexp.MustCompile(`^/apis/[^/]+/[^/]+/([^/]+)/?$`), []string{"resource"}, false},
}

// ExtractK8sFacets is the built-in Kubernetes extractor. Reads sub["method"]
// and sub["path"] and returns {verb, resource, namespace, name, subresource}.
func ExtractK8sFacets(sub map[string]any) map[string]any {
	method := ""
	if s, ok := sub["method"].(string); ok {
		method = strings.ToUpper(s)
	}
	rawPath := ""
	if s, ok := sub["path"].(string); ok {
		rawPath = s
	}

	out := map[string]any{
		"verb": "", "resource": "", "namespace": "", "name": "", "subresource": "",
	}
	if rawPath == "" {
		return out
	}

	// Strip query / fragment before matching so resources or namespaces with
	// names containing "watch" cannot spoof the verb signal, and honor
	// ?watch=true as an alternate watch indicator.
	pathOnly := rawPath
	query := ""
	if idx := strings.IndexByte(pathOnly, '?'); idx >= 0 {
		query = pathOnly[idx+1:]
		pathOnly = pathOnly[:idx]
	}
	if idx := strings.IndexByte(pathOnly, '#'); idx >= 0 {
		pathOnly = pathOnly[:idx]
	}

	matched := map[string]string{}
	matchedIsWatch := false
	for _, pat := range k8sPatterns {
		m := pat.re.FindStringSubmatch(pathOnly)
		if m == nil {
			continue
		}
		for i, g := range pat.groups {
			matched[g] = m[i+1]
		}
		matchedIsWatch = pat.isWatch
		break
	}

	queryIsWatch := false
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				continue
			}
			if kv[:eq] == "watch" {
				v := kv[eq+1:]
				if v == "true" || v == "1" || v == "True" {
					queryIsWatch = true
					break
				}
			}
		}
	}

	resource := matched["resource"]
	namespace := matched["namespace"]
	name := matched["name"]
	subresource := matched["subresource"]

	// watch is read-only; only gate on GET / HEAD / empty so a write method
	// with ?watch=true doesn't silently classify as a benign watch.
	methodAllowsWatch := method == "" || method == "GET" || method == "HEAD"
	isWatch := (matchedIsWatch || queryIsWatch) && methodAllowsWatch

	var verb string
	switch {
	case isWatch:
		verb = "watch"
	case method != "":
		tbl := methodToVerbCollection
		if name != "" {
			tbl = methodToVerbNamed
		}
		if v, ok := tbl[method]; ok {
			verb = v
		} else {
			verb = strings.ToLower(method)
		}
	}

	out["verb"] = verb
	out["resource"] = resource
	out["namespace"] = namespace
	out["name"] = name
	out["subresource"] = subresource
	return out
}
