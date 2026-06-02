// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func makeCredStack(t *testing.T) (*CredentialVault, *CredentialInjector) {
	t.Helper()
	v := NewCredentialVault()
	if _, err := v.Put("github_pat", "GHP-RESOLVED-VALUE", "bearer_token"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := v.Put("db_password", "DBP-VALUE", "password"); err != nil {
		t.Fatalf("put: %v", err)
	}
	v.RegisterProfile(NewCredentialProfile("did:web:agent-ci", map[string]string{
		"github:read_issues": "github_pat",
		"github:push_code":   "github_pat",
	}))
	v.RegisterProfile(NewCredentialProfile("did:web:agent-analytics", map[string]string{
		"db:query": "db_password",
	}))
	return v, NewCredentialInjector(v)
}

func TestCredentialPut_ReturnsHandle(t *testing.T) {
	v := NewCredentialVault()
	h, err := v.Put("k1", "v1", "secret")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if h.Name != "k1" {
		t.Fatalf("got %q", h.Name)
	}
	if h.Placeholder() != "{{cred:k1}}" {
		t.Fatalf("got %q", h.Placeholder())
	}
}

func TestCredentialPut_RejectsBadNames(t *testing.T) {
	v := NewCredentialVault()
	for _, name := range []string{"", "bad name", strings.Repeat("a", 200)} {
		if _, err := v.Put(name, "v", "s"); err == nil {
			t.Errorf("expected error for name %q", name)
		}
	}
}

func TestCredentialList_NoValueLeak(t *testing.T) {
	v, _ := makeCredStack(t)
	names, _ := v.ListHandles()
	wantA, wantB := "db_password", "github_pat"
	if len(names) != 2 || names[0] != wantA || names[1] != wantB {
		t.Fatalf("got %v", names)
	}
	for _, n := range names {
		meta, _ := v.Metadata(n)
		js, _ := json.Marshal(meta)
		if strings.Contains(string(js), "GHP-RESOLVED-VALUE") {
			t.Fatalf("metadata leaked value: %s", js)
		}
	}
}

func TestCredentialRotate_PreservesHandle_BumpsVersion(t *testing.T) {
	v, _ := makeCredStack(t)
	before, _ := v.Metadata("github_pat")
	if before.Version != 1 {
		t.Fatalf("expected v1, got %d", before.Version)
	}
	h, err := v.Rotate("github_pat", "ghp_new")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if h.Name != "github_pat" {
		t.Fatalf("rotate changed name: %q", h.Name)
	}
	after, _ := v.Metadata("github_pat")
	if after.Version != 2 {
		t.Fatalf("expected v2, got %d", after.Version)
	}
	if after.RotatedAt == nil {
		t.Fatalf("expected rotatedAt to be set")
	}
}

func TestCredentialRotate_Unknown_Errors(t *testing.T) {
	v, _ := makeCredStack(t)
	if _, err := v.Rotate("nope", "x"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCredentialDelete_PresenceFlag(t *testing.T) {
	v, _ := makeCredStack(t)
	first, _ := v.Delete("db_password")
	second, _ := v.Delete("db_password")
	if !first || second {
		t.Fatalf("got first=%v second=%v", first, second)
	}
}

func TestCredentialCheckAccess(t *testing.T) {
	v, _ := makeCredStack(t)
	if !v.CheckAccess("did:web:agent-ci", "github_pat", "github:read_issues") {
		t.Fatalf("expected allow")
	}
	if v.CheckAccess("did:web:rogue", "github_pat", "github:read_issues") {
		t.Fatalf("expected deny for unknown agent")
	}
	if v.CheckAccess("did:web:agent-ci", "db_password", "db:query") {
		t.Fatalf("expected deny for unbound action")
	}
	if v.CheckAccess("did:web:agent-analytics", "db_password", "db:admin") {
		t.Fatalf("expected deny for cross-action reuse")
	}
}

func TestCredentialInjectHeaders_HappyPath(t *testing.T) {
	v, i := makeCredStack(t)
	r := i.InjectHeaders("did:web:agent-ci",
		map[string]string{
			"Authorization": "Bearer {{cred:github_pat}}",
			"Accept":        "application/json",
		},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "api.github.com",
			AllowedHandles: []string{"github_pat"},
			PolicyVersion:  "v1",
		})
	if !r.Allowed {
		t.Fatalf("expected allow, got %+v", r)
	}
	got := r.Payload.(map[string]string)
	if got["Authorization"] != "Bearer GHP-RESOLVED-VALUE" {
		t.Fatalf("got %q", got["Authorization"])
	}
	events := v.AuditLog()
	if len(events) != 1 || events[0].Decision != CredentialAllow {
		t.Fatalf("unexpected audit %+v", events)
	}
}

func TestCredentialInjectToolArgs_Nested(t *testing.T) {
	_, i := makeCredStack(t)
	args := map[string]interface{}{
		"repo":    "octo/hello",
		"secrets": []interface{}{"{{cred:github_pat}}", "literal"},
		"nested":  map[string]interface{}{"token": "{{cred:github_pat}}"},
	}
	r := i.InjectToolArgs("did:web:agent-ci", args, InjectionOptions{
		ActionClass:    "github:push_code",
		TargetService:  "api.github.com",
		AllowedHandles: []string{"github_pat"},
	})
	if !r.Allowed {
		t.Fatalf("expected allow, got %+v", r)
	}
	out := r.Payload.(map[string]interface{})
	if out["secrets"].([]interface{})[0].(string) != "GHP-RESOLVED-VALUE" {
		t.Fatalf("secrets[0] not rendered: %v", out["secrets"])
	}
	if out["nested"].(map[string]interface{})["token"].(string) != "GHP-RESOLVED-VALUE" {
		t.Fatalf("nested.token not rendered: %v", out["nested"])
	}
}

func TestCredentialInjectEnv(t *testing.T) {
	_, i := makeCredStack(t)
	r := i.InjectEnv("did:web:agent-ci",
		map[string]string{"PATH": "/usr/bin", "GITHUB_TOKEN": "{{cred:github_pat}}"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "subprocess",
			AllowedHandles: []string{"github_pat"},
		})
	if !r.Allowed {
		t.Fatalf("expected allow")
	}
	if r.Payload.(map[string]string)["GITHUB_TOKEN"] != "GHP-RESOLVED-VALUE" {
		t.Fatalf("not rendered")
	}
}

func TestCredentialUnauthorizedPlaceholder_DeniesWholeCall(t *testing.T) {
	_, i := makeCredStack(t)
	r := i.InjectToolArgs("did:web:agent-analytics",
		map[string]interface{}{"sql": "SELECT 1", "auth": "{{cred:github_pat}}"},
		InjectionOptions{
			ActionClass:    "db:query",
			TargetService:  "pg",
			AllowedHandles: []string{"db_password"},
		})
	if r.Allowed {
		t.Fatalf("expected deny")
	}
	if r.DenyReceipt.Reason != CredentialDenyReason {
		t.Fatalf("expected DENY_REASON, got %q", r.DenyReceipt.Reason)
	}
}

func TestCredentialMissing_And_OutOfScope_IdenticalDeny(t *testing.T) {
	_, i := makeCredStack(t)
	missing := i.InjectHeaders("did:web:agent-ci",
		map[string]string{"X": "{{cred:does_not_exist}}"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "svc",
			AllowedHandles: []string{"does_not_exist"},
		})
	outOfScope := i.InjectHeaders("did:web:agent-ci",
		map[string]string{"X": "{{cred:db_password}}"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "svc",
			AllowedHandles: []string{"db_password"},
		})
	if missing.Allowed || outOfScope.Allowed {
		t.Fatalf("expected both denied")
	}
	if !missing.DenyReceipt.Equals(*outOfScope.DenyReceipt) {
		t.Fatalf("deny receipts differ")
	}
}

func TestCredentialPolicy_RunsBeforeVaultRead(t *testing.T) {
	_, i := makeCredStack(t)
	var seen []string
	var mu sync.Mutex
	r := i.InjectHeaders("did:web:agent-ci",
		map[string]string{"Authorization": "Bearer {{cred:github_pat}}"},
		InjectionOptions{
			ActionClass:    "github:push_code",
			TargetService:  "api.github.com",
			AllowedHandles: []string{"github_pat"},
			PolicyVersion:  "v7",
			PolicyCheck: func(ctx InjectionContext) PolicyOutcome {
				mu.Lock()
				seen = append(seen, ctx.RequestedHandles...)
				mu.Unlock()
				return PolicyOutcome{Allow: false, Reason: "no"}
			},
		})
	if r.Allowed {
		t.Fatalf("expected deny")
	}
	if len(seen) != 1 || seen[0] != "github_pat" {
		t.Fatalf("policy didn't see requested handles: %v", seen)
	}
}

func TestCredentialSameDenyAcrossSurfaces(t *testing.T) {
	_, i := makeCredStack(t)
	opts := InjectionOptions{
		ActionClass:    "db:query",
		TargetService:  "svc",
		AllowedHandles: []string{"github_pat"},
	}
	h := i.InjectHeaders("did:web:agent-analytics",
		map[string]string{"Authorization": "{{cred:github_pat}}"}, opts)
	a := i.InjectToolArgs("did:web:agent-analytics",
		map[string]interface{}{"x": "{{cred:github_pat}}"}, opts)
	e := i.InjectEnv("did:web:agent-analytics",
		map[string]string{"TOKEN": "{{cred:github_pat}}"}, opts)
	for _, r := range []InjectionResult{h, a, e} {
		if r.Allowed || r.DenyReceipt.Reason != CredentialDenyReason {
			t.Fatalf("expected deny: %+v", r)
		}
	}
}

func TestCredentialPayloadWithoutPlaceholders(t *testing.T) {
	_, i := makeCredStack(t)
	r := i.InjectHeaders("did:web:agent-ci",
		map[string]string{"Accept": "application/json"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "svc",
			AllowedHandles: nil,
		})
	if !r.Allowed {
		t.Fatalf("expected allow")
	}
}

func TestCredentialAudit_NoValueLeak(t *testing.T) {
	v, i := makeCredStack(t)
	i.InjectHeaders("did:web:agent-ci",
		map[string]string{"Authorization": "Bearer {{cred:github_pat}}"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "svc",
			AllowedHandles: []string{"github_pat"},
			PolicyVersion:  "v1",
		})
	events := v.AuditLog()
	js, _ := json.Marshal(events)
	if strings.Contains(string(js), "GHP-RESOLVED-VALUE") {
		t.Fatalf("audit leaked value")
	}
}

func TestCredentialAuditDigest_StableAndKeyDependent(t *testing.T) {
	v, i := makeCredStack(t)
	i.InjectHeaders("did:web:agent-ci",
		map[string]string{"Authorization": "Bearer {{cred:github_pat}}"},
		InjectionOptions{
			ActionClass:    "github:read_issues",
			TargetService:  "svc",
			AllowedHandles: []string{"github_pat"},
		})
	events := v.AuditLog()
	a := CredentialAuditDigest(events, []byte("k"))
	b := CredentialAuditDigest(events, []byte("k"))
	c := CredentialAuditDigest(events, []byte("other"))
	if a != b {
		t.Fatalf("digest not stable")
	}
	if a == c {
		t.Fatalf("digest not key-dependent")
	}
}

func TestCredentialRotation_DoesNotRequirePromptChanges(t *testing.T) {
	v := NewCredentialVault()
	if _, err := v.Put("github_pat", "GHP-V1", "secret"); err != nil {
		t.Fatal(err)
	}
	v.RegisterProfile(NewCredentialProfile("did:web:agent-ci", map[string]string{
		"github:read_issues": "github_pat",
	}))
	i := NewCredentialInjector(v)
	saved := map[string]string{"Authorization": "Bearer {{cred:github_pat}}"}
	opts := InjectionOptions{
		ActionClass: "github:read_issues", TargetService: "svc",
		AllowedHandles: []string{"github_pat"},
	}
	before := i.InjectHeaders("did:web:agent-ci", saved, opts)
	if before.Payload.(map[string]string)["Authorization"] != "Bearer GHP-V1" {
		t.Fatalf("before: %v", before.Payload)
	}
	if _, err := v.Rotate("github_pat", "GHP-V2"); err != nil {
		t.Fatal(err)
	}
	after := i.InjectHeaders("did:web:agent-ci", saved, opts)
	if after.Payload.(map[string]string)["Authorization"] != "Bearer GHP-V2" {
		t.Fatalf("after: %v", after.Payload)
	}
	if saved["Authorization"] != "Bearer {{cred:github_pat}}" {
		t.Fatalf("saved was mutated")
	}
}

func TestCredentialEncryptedPersistence_RoundTrip(t *testing.T) {
	key, err := GenerateCredentialKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	secret := "distinctive rotated fixture not a real key" // gitleaks:allow

	v1, err := NewPersistentCredentialVault(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.Put("k", "original", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := v1.Rotate("k", secret); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(secret)) {
		t.Fatal("secret appeared in encrypted blob")
	}
	if bytes.Contains(blob, []byte(`"value"`)) {
		t.Fatal("value key appeared in encrypted blob")
	}

	v2, err := NewPersistentCredentialVault(path, key)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := v2.ListHandles()
	if len(names) != 1 || names[0] != "k" {
		t.Fatalf("got %v", names)
	}
	meta, _ := v2.Metadata("k")
	if meta.Version != 2 {
		t.Fatalf("got version %d", meta.Version)
	}
}

func TestCredentialPersistence_RequiresCorrectKeyLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.bin")
	if _, err := NewPersistentCredentialVault(path, make([]byte, 16)); err == nil {
		t.Fatal("expected error")
	}
}
