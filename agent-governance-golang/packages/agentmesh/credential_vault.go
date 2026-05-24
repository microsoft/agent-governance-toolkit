// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package agentmesh credential_vault.go — Credential vault, scoping, and
// injection for agent tool calls.
//
// Go port of the Python `agent_os.credential_vault` primitive (issue
// #2481, PR #2534). Tracking issue: #2535.
//
// Agents reference secrets via opaque {{cred:NAME}} placeholders only;
// resolved values stay inside the trust boundary.
//
// Wire-format note: this SDK uses AES-256-GCM (crypto/aes + crypto/cipher)
// with a 12-byte random nonce prefixed to the ciphertext. The Python SDK
// uses Fernet. The two persistence formats are not currently interoperable
// — the cross-language interop spec is tracked in #2535.
package agentmesh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// CredentialDenyReason is the stable string returned in audit/deny records when a request is refused.
const CredentialDenyReason = "credential_denied"

const (
	credKeyLength   = 32
	credNonceLength = 12
)

// CredentialPlaceholderRegex matches the credential placeholder syntax {{cred:NAME}}.
var CredentialPlaceholderRegex = regexp.MustCompile(`\{\{\s*cred:([A-Za-z0-9_.\-]{1,128})\s*\}\}`)

var credNameRegex = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)

// CredentialDecision is the outcome of a credential resolution attempt.
type CredentialDecision string

const (
	// CredentialAllow means the request was allowed.
	CredentialAllow CredentialDecision = "allow"
	// CredentialDeny means the request was denied.
	CredentialDeny CredentialDecision = "deny"
)

// Errors returned by the credential vault.
var (
	// ErrCredentialInvalidName is returned when a credential name fails validation.
	ErrCredentialInvalidName = errors.New("invalid credential name: must match [A-Za-z0-9_.-]{1,128}")
	// ErrCredentialUnknown is returned when the named credential does not exist.
	ErrCredentialUnknown = errors.New("unknown credential")
	// ErrCredentialKeyRequired is returned when a persistent vault is created without an encryption key.
	ErrCredentialKeyRequired = errors.New("encryption key required when persistence is configured")
	// ErrCredentialBadKeyLength is returned when the encryption key is not 32 bytes.
	ErrCredentialBadKeyLength = fmt.Errorf("encryption key must be exactly %d bytes", credKeyLength)
)

// CredentialRecord is an internal credential entry. Never exposed to agents.
type CredentialRecord struct {
	Name      string   `json:"name"`
	Value     string   `json:"value"`
	CredType  string   `json:"credType"`
	Version   int      `json:"version"`
	CreatedAt float64  `json:"createdAt"`
	RotatedAt *float64 `json:"rotatedAt,omitempty"`
}

// CredentialMetadata is the non-secret view of a credential.
type CredentialMetadata struct {
	Name      string   `json:"name"`
	CredType  string   `json:"credType"`
	Version   int      `json:"version"`
	CreatedAt float64  `json:"createdAt"`
	RotatedAt *float64 `json:"rotatedAt,omitempty"`
}

// CredentialHandle is the opaque handle an agent may reference.
type CredentialHandle struct {
	Name string
}

// Placeholder returns the {{cred:NAME}} placeholder for this handle.
func (h CredentialHandle) Placeholder() string {
	return "{{cred:" + h.Name + "}}"
}

// CredentialProfile binds action capabilities to credential handle names for one agent DID.
type CredentialProfile struct {
	AgentDID string
	bindings map[string]string
}

// NewCredentialProfile creates a profile mapping action classes to handle names.
func NewCredentialProfile(agentDID string, bindings map[string]string) *CredentialProfile {
	copied := make(map[string]string, len(bindings))
	for k, v := range bindings {
		copied[k] = v
	}
	return &CredentialProfile{AgentDID: agentDID, bindings: copied}
}

// CapabilityFor returns the handle name bound to the action class, or "" if absent.
func (p *CredentialProfile) CapabilityFor(actionClass string) string {
	return p.bindings[actionClass]
}

// Bindings returns a copy of the capability bindings.
func (p *CredentialProfile) Bindings() map[string]string {
	out := make(map[string]string, len(p.bindings))
	for k, v := range p.bindings {
		out[k] = v
	}
	return out
}

// VaultAuditEvent is a single audit record. Contains agent identity, handle
// name, target service, action class, decision, and policy version — but
// never the resolved credential value.
type VaultAuditEvent struct {
	Timestamp     float64            `json:"timestamp"`
	AgentDID      string             `json:"agentDid"`
	HandleName    string             `json:"handleName"`
	TargetService string             `json:"targetService"`
	ActionClass   string             `json:"actionClass"`
	Decision      CredentialDecision `json:"decision"`
	PolicyVersion string             `json:"policyVersion"`
	Reason        string             `json:"reason"`
}

// DenyReceipt is the deterministic deny output returned in place of a rendered payload.
type DenyReceipt struct {
	Reason        string `json:"reason"`
	ActionClass   string `json:"actionClass"`
	TargetService string `json:"targetService"`
}

func newDenyReceipt(actionClass, targetService string) DenyReceipt {
	return DenyReceipt{
		Reason:        CredentialDenyReason,
		ActionClass:   actionClass,
		TargetService: targetService,
	}
}

// Equals reports whether two deny receipts have identical fields.
func (d DenyReceipt) Equals(other DenyReceipt) bool {
	return d.Reason == other.Reason &&
		d.ActionClass == other.ActionClass &&
		d.TargetService == other.TargetService
}

type credPersistPayload struct {
	Records []CredentialRecord `json:"records"`
}

// CredentialVault is an encrypted-at-rest credential store and scoped resolver.
type CredentialVault struct {
	mu          sync.Mutex
	records     map[string]CredentialRecord
	profiles    map[string]*CredentialProfile
	audit       []VaultAuditEvent
	persistPath string
	key         []byte
	loaded      bool
}

// NewCredentialVault creates an in-memory vault.
func NewCredentialVault() *CredentialVault {
	return &CredentialVault{
		records:  make(map[string]CredentialRecord),
		profiles: make(map[string]*CredentialProfile),
		loaded:   true,
	}
}

// NewPersistentCredentialVault creates a vault with encrypted-at-rest persistence.
func NewPersistentCredentialVault(persistPath string, encryptionKey []byte) (*CredentialVault, error) {
	if persistPath == "" {
		return nil, errors.New("persistPath must be non-empty")
	}
	if len(encryptionKey) != credKeyLength {
		return nil, ErrCredentialBadKeyLength
	}
	keyCopy := make([]byte, credKeyLength)
	copy(keyCopy, encryptionKey)
	v := &CredentialVault{
		records:     make(map[string]CredentialRecord),
		profiles:    make(map[string]*CredentialProfile),
		persistPath: persistPath,
		key:         keyCopy,
	}
	if err := v.ensureLoaded(); err != nil {
		return nil, err
	}
	return v, nil
}

// GenerateCredentialKey generates a fresh AES-256-GCM key (32 random bytes).
func GenerateCredentialKey() ([]byte, error) {
	k := make([]byte, credKeyLength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// -- Admin surface ----------------------------------------------------------

// Put stores or replaces a credential.
func (v *CredentialVault) Put(name, value, credType string) (CredentialHandle, error) {
	if !credNameRegex.MatchString(name) {
		return CredentialHandle{}, ErrCredentialInvalidName
	}
	if err := v.ensureLoaded(); err != nil {
		return CredentialHandle{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := nowSeconds()
	rec := CredentialRecord{
		Name:     name,
		Value:    value,
		CredType: credType,
		Version:  1,
	}
	if existing, ok := v.records[name]; ok {
		rec.Version = existing.Version + 1
		rec.CreatedAt = existing.CreatedAt
		rotatedAt := now
		rec.RotatedAt = &rotatedAt
	} else {
		rec.CreatedAt = now
	}
	v.records[name] = rec
	if err := v.flushLocked(); err != nil {
		return CredentialHandle{}, err
	}
	return CredentialHandle{Name: name}, nil
}

// Rotate rotates a credential's value while preserving the handle name.
func (v *CredentialVault) Rotate(name, newValue string) (CredentialHandle, error) {
	if err := v.ensureLoaded(); err != nil {
		return CredentialHandle{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	old, ok := v.records[name]
	if !ok {
		return CredentialHandle{}, fmt.Errorf("%w: %s", ErrCredentialUnknown, name)
	}
	rotatedAt := nowSeconds()
	old.Value = newValue
	old.Version++
	old.RotatedAt = &rotatedAt
	v.records[name] = old
	if err := v.flushLocked(); err != nil {
		return CredentialHandle{}, err
	}
	return CredentialHandle{Name: name}, nil
}

// Delete removes a credential. Returns true if it existed.
func (v *CredentialVault) Delete(name string) (bool, error) {
	if err := v.ensureLoaded(); err != nil {
		return false, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.records[name]; !ok {
		return false, nil
	}
	delete(v.records, name)
	if err := v.flushLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// ListHandles returns all credential handle names.
func (v *CredentialVault) ListHandles() ([]string, error) {
	if err := v.ensureLoaded(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	names := make([]string, 0, len(v.records))
	for k := range v.records {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// Metadata returns non-secret metadata for a credential, or (nil, nil) if absent.
func (v *CredentialVault) Metadata(name string) (*CredentialMetadata, error) {
	if err := v.ensureLoaded(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	r, ok := v.records[name]
	if !ok {
		return nil, nil
	}
	return &CredentialMetadata{
		Name:      r.Name,
		CredType:  r.CredType,
		Version:   r.Version,
		CreatedAt: r.CreatedAt,
		RotatedAt: r.RotatedAt,
	}, nil
}

// RegisterProfile registers or replaces a per-agent profile.
func (v *CredentialVault) RegisterProfile(p *CredentialProfile) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.profiles[p.AgentDID] = p
}

// RevokeProfile revokes a profile by agent DID. Returns true if it existed.
func (v *CredentialVault) RevokeProfile(agentDID string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.profiles[agentDID]; ok {
		delete(v.profiles, agentDID)
		return true
	}
	return false
}

// -- Resolver surface -------------------------------------------------------

// CheckAccess returns true iff agentDID may use handleName for actionClass.
func (v *CredentialVault) CheckAccess(agentDID, handleName, actionClass string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.checkAccessLocked(agentDID, handleName, actionClass)
}

func (v *CredentialVault) checkAccessLocked(agentDID, handleName, actionClass string) bool {
	profile, ok := v.profiles[agentDID]
	if !ok {
		return false
	}
	bound := profile.CapabilityFor(actionClass)
	if bound == "" || bound != handleName {
		return false
	}
	_, present := v.records[handleName]
	return present
}

// AuditLog returns a snapshot of audit events.
func (v *CredentialVault) AuditLog() []VaultAuditEvent {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]VaultAuditEvent, len(v.audit))
	copy(out, v.audit)
	return out
}

// ClearAudit removes all audit events.
func (v *CredentialVault) ClearAudit() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.audit = nil
}

func (v *CredentialVault) resolveInternal(
	agentDID, handleName, actionClass, targetService, policyVersion string,
) (string, bool, VaultAuditEvent) {
	v.mu.Lock()
	defer v.mu.Unlock()
	allowed := v.checkAccessLocked(agentDID, handleName, actionClass)
	if allowed {
		value := v.records[handleName].Value
		ev := VaultAuditEvent{
			Timestamp:     nowSeconds(),
			AgentDID:      agentDID,
			HandleName:    handleName,
			TargetService: targetService,
			ActionClass:   actionClass,
			Decision:      CredentialAllow,
			PolicyVersion: policyVersion,
		}
		v.audit = append(v.audit, ev)
		return value, true, ev
	}
	ev := VaultAuditEvent{
		Timestamp:     nowSeconds(),
		AgentDID:      agentDID,
		HandleName:    handleName,
		TargetService: targetService,
		ActionClass:   actionClass,
		Decision:      CredentialDeny,
		PolicyVersion: policyVersion,
		Reason:        CredentialDenyReason,
	}
	v.audit = append(v.audit, ev)
	return "", false, ev
}

func (v *CredentialVault) recordReject(ev VaultAuditEvent) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.audit = append(v.audit, ev)
}

// -- Persistence ------------------------------------------------------------

func (v *CredentialVault) ensureLoaded() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.loaded {
		return nil
	}
	v.loaded = true
	if v.persistPath == "" || v.key == nil {
		return nil
	}
	blob, err := os.ReadFile(v.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(blob) == 0 {
		return nil
	}
	plaintext, err := credDecrypt(v.key, blob)
	if err != nil {
		return err
	}
	var payload credPersistPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return err
	}
	for _, r := range payload.Records {
		v.records[r.Name] = r
	}
	return nil
}

func (v *CredentialVault) flushLocked() error {
	if v.persistPath == "" || v.key == nil {
		return nil
	}
	records := make([]CredentialRecord, 0, len(v.records))
	for _, r := range v.records {
		records = append(records, r)
	}
	plaintext, err := json.Marshal(credPersistPayload{Records: records})
	if err != nil {
		return err
	}
	blob, err := credEncrypt(v.key, plaintext)
	if err != nil {
		return err
	}
	dir := filepath.Dir(v.persistPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := v.persistPath + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.persistPath)
}

func credEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, credNonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func credDecrypt(key, blob []byte) ([]byte, error) {
	if len(blob) < credNonceLength {
		return nil, errors.New("persisted vault is corrupt (too short)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := blob[:credNonceLength], blob[credNonceLength:]
	return gcm.Open(nil, nonce, ct, nil)
}

func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// -- Injector ---------------------------------------------------------------

// InjectionContext is information presented to the workflow policy before resolution.
type InjectionContext struct {
	AgentDID         string
	ActionClass      string
	TargetService    string
	RequestedHandles []string
	PolicyVersion    string
}

// PolicyOutcome is the result returned by the workflow policy callback.
type PolicyOutcome struct {
	Allow  bool
	Reason string
}

// PolicyCheck is the workflow-policy callback type.
type PolicyCheck func(ctx InjectionContext) PolicyOutcome

// InjectionResult is the outcome of an injection call.
type InjectionResult struct {
	Allowed     bool
	Payload     interface{}
	DenyReceipt *DenyReceipt
	AuditEvents []VaultAuditEvent
}

// InjectionOptions are options for an injection call.
type InjectionOptions struct {
	ActionClass    string
	TargetService  string
	AllowedHandles []string
	PolicyVersion  string
	PolicyCheck    PolicyCheck
}

// CredentialInjector renders {{cred:NAME}} placeholders into HTTP, MCP, and env payloads.
//
// The injector is the only component that ever holds resolved credential
// values, and only long enough to render an outbound payload.
type CredentialInjector struct {
	vault *CredentialVault
}

// NewCredentialInjector constructs an injector backed by the given vault.
func NewCredentialInjector(v *CredentialVault) *CredentialInjector {
	return &CredentialInjector{vault: v}
}

// InjectHeaders renders placeholders in an HTTP header map.
func (i *CredentialInjector) InjectHeaders(
	agentDID string, headers map[string]string, opts InjectionOptions,
) InjectionResult {
	clone := make(map[string]string, len(headers))
	for k, v := range headers {
		clone[k] = v
	}
	return i.inject(agentDID, clone, opts)
}

// InjectToolArgs renders placeholders in MCP tool arguments (nested map/slice/string).
func (i *CredentialInjector) InjectToolArgs(
	agentDID string, args interface{}, opts InjectionOptions,
) InjectionResult {
	return i.inject(agentDID, args, opts)
}

// InjectEnv renders placeholders in a subprocess environment map.
func (i *CredentialInjector) InjectEnv(
	agentDID string, env map[string]string, opts InjectionOptions,
) InjectionResult {
	clone := make(map[string]string, len(env))
	for k, v := range env {
		clone[k] = v
	}
	return i.inject(agentDID, clone, opts)
}

func (i *CredentialInjector) inject(
	agentDID string, payload interface{}, opts InjectionOptions,
) InjectionResult {
	if opts.PolicyVersion == "" {
		opts.PolicyVersion = "v0"
	}
	allowlist := make(map[string]struct{}, len(opts.AllowedHandles))
	for _, h := range opts.AllowedHandles {
		allowlist[h] = struct{}{}
	}
	requested := credCollectPlaceholders(payload)

	// 1. Reject anything outside the allowlist.
	var outside []string
	for _, n := range requested {
		if _, ok := allowlist[n]; !ok {
			outside = append(outside, n)
		}
	}
	if len(outside) > 0 {
		ev := VaultAuditEvent{
			Timestamp:     nowSeconds(),
			AgentDID:      agentDID,
			HandleName:    outside[0],
			TargetService: opts.TargetService,
			ActionClass:   opts.ActionClass,
			Decision:      CredentialDeny,
			PolicyVersion: opts.PolicyVersion,
			Reason:        CredentialDenyReason,
		}
		i.vault.recordReject(ev)
		deny := newDenyReceipt(opts.ActionClass, opts.TargetService)
		return InjectionResult{
			Allowed:     false,
			Payload:     deny,
			DenyReceipt: &deny,
			AuditEvents: []VaultAuditEvent{ev},
		}
	}

	// 2. Run policy BEFORE any vault read.
	if opts.PolicyCheck != nil {
		ctx := InjectionContext{
			AgentDID:         agentDID,
			ActionClass:      opts.ActionClass,
			TargetService:    opts.TargetService,
			RequestedHandles: append([]string(nil), requested...),
			PolicyVersion:    opts.PolicyVersion,
		}
		outcome := opts.PolicyCheck(ctx)
		if !outcome.Allow {
			handleName := ""
			if len(requested) > 0 {
				handleName = requested[0]
			}
			ev := VaultAuditEvent{
				Timestamp:     nowSeconds(),
				AgentDID:      agentDID,
				HandleName:    handleName,
				TargetService: opts.TargetService,
				ActionClass:   opts.ActionClass,
				Decision:      CredentialDeny,
				PolicyVersion: opts.PolicyVersion,
				Reason:        CredentialDenyReason,
			}
			i.vault.recordReject(ev)
			deny := newDenyReceipt(opts.ActionClass, opts.TargetService)
			return InjectionResult{
				Allowed:     false,
				Payload:     deny,
				DenyReceipt: &deny,
				AuditEvents: []VaultAuditEvent{ev},
			}
		}
	}

	// 3. Resolve. Any single deny aborts the whole call.
	resolved := make(map[string]string)
	var events []VaultAuditEvent
	for _, name := range requested {
		value, ok, ev := i.vault.resolveInternal(
			agentDID, name, opts.ActionClass, opts.TargetService, opts.PolicyVersion)
		events = append(events, ev)
		if !ok {
			deny := newDenyReceipt(opts.ActionClass, opts.TargetService)
			return InjectionResult{
				Allowed:     false,
				Payload:     deny,
				DenyReceipt: &deny,
				AuditEvents: events,
			}
		}
		resolved[name] = value
	}

	rendered := credSubstitute(payload, resolved)
	return InjectionResult{
		Allowed:     true,
		Payload:     rendered,
		AuditEvents: events,
	}
}

// credCollectPlaceholders walks a nested structure and returns the sorted set of placeholder names found.
func credCollectPlaceholders(payload interface{}) []string {
	seen := make(map[string]struct{})
	credWalk(payload, func(s string) {
		for _, m := range CredentialPlaceholderRegex.FindAllStringSubmatch(s, -1) {
			seen[m[1]] = struct{}{}
		}
	})
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func credWalk(payload interface{}, visit func(string)) {
	switch p := payload.(type) {
	case nil:
		return
	case string:
		visit(p)
	case map[string]string:
		for k, v := range p {
			visit(k)
			visit(v)
		}
	case map[string]interface{}:
		for k, v := range p {
			visit(k)
			credWalk(v, visit)
		}
	case []interface{}:
		for _, item := range p {
			credWalk(item, visit)
		}
	case []string:
		for _, item := range p {
			visit(item)
		}
	}
}

func credSubstitute(payload interface{}, resolved map[string]string) interface{} {
	return credMapStrings(payload, func(s string) string {
		return CredentialPlaceholderRegex.ReplaceAllStringFunc(s, func(m string) string {
			caps := CredentialPlaceholderRegex.FindStringSubmatch(m)
			if v, ok := resolved[caps[1]]; ok {
				return v
			}
			return m
		})
	})
}

func credMapStrings(payload interface{}, fn func(string) string) interface{} {
	switch p := payload.(type) {
	case string:
		return fn(p)
	case map[string]string:
		out := make(map[string]string, len(p))
		for k, v := range p {
			out[fn(k)] = fn(v)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(p))
		for k, v := range p {
			out[fn(k)] = credMapStrings(v, fn)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(p))
		for i, item := range p {
			out[i] = credMapStrings(item, fn)
		}
		return out
	case []string:
		out := make([]string, len(p))
		for i, item := range p {
			out[i] = fn(item)
		}
		return out
	default:
		return payload
	}
}

// CredentialAuditDigest computes a stable HMAC-SHA256 digest of an audit-event
// sequence. The digest covers handle names and decisions but never references
// resolved credential values.
func CredentialAuditDigest(events []VaultAuditEvent, key []byte) string {
	h := hmac.New(sha256.New, key)
	for _, ev := range events {
		js, _ := json.Marshal(ev)
		h.Write(js)
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}
