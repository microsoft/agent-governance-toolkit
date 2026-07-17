// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"errors"
	"sync"
)

var (
	// ErrApprovalRequestNotFound is returned when a store lookup misses.
	ErrApprovalRequestNotFound = errors.New("approval request not found")

	// ErrApprovalRequestExists is returned when a duplicate request is inserted.
	ErrApprovalRequestExists = errors.New("approval request already exists")
)

// ApprovalStore persists approval requests, entries, and resolutions.
type ApprovalStore interface {
	SaveRequest(policy ApprovalPolicyDecisionRecord, request ApprovalRequest) error
	GetRequest(approvalRequestID string) (ApprovalPolicyDecisionRecord, ApprovalRequest, bool)
	UpdateRequestStatus(approvalRequestID string, status ApprovalStatus) (ApprovalRequest, bool)
	AppendEntry(entry ApprovalChainEntry) error
	ListEntries(approvalRequestID string) ([]ApprovalChainEntry, bool)
	SaveResolution(resolution ApprovalResolution) error
	GetResolution(approvalRequestID string) (ApprovalResolution, bool)
	ConsumeApproval(approvalRequestID string) (ApprovalRequest, bool)
}

type approvalStoreRecord struct {
	policy     ApprovalPolicyDecisionRecord
	request    ApprovalRequest
	entries    []ApprovalChainEntry
	resolution *ApprovalResolution
}

// InMemoryApprovalStore is a concurrency-safe process-local ApprovalStore.
type InMemoryApprovalStore struct {
	mu      sync.RWMutex
	records map[string]*approvalStoreRecord
}

// NewInMemoryApprovalStore creates an empty in-memory approval store.
func NewInMemoryApprovalStore() *InMemoryApprovalStore {
	return &InMemoryApprovalStore{
		records: make(map[string]*approvalStoreRecord),
	}
}

// SaveRequest stores a newly opened approval request.
func (s *InMemoryApprovalStore) SaveRequest(policy ApprovalPolicyDecisionRecord, request ApprovalRequest) error {
	if s == nil {
		return ErrApprovalRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureRecordsLocked()
	if _, exists := s.records[request.ApprovalRequestID]; exists {
		return ErrApprovalRequestExists
	}
	s.records[request.ApprovalRequestID] = &approvalStoreRecord{
		policy:  policy,
		request: request,
	}
	return nil
}

// GetRequest returns the policy decision and request by id.
func (s *InMemoryApprovalStore) GetRequest(approvalRequestID string) (ApprovalPolicyDecisionRecord, ApprovalRequest, bool) {
	if s == nil {
		return ApprovalPolicyDecisionRecord{}, ApprovalRequest{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[approvalRequestID]
	if !ok {
		return ApprovalPolicyDecisionRecord{}, ApprovalRequest{}, false
	}
	return record.policy, record.request, true
}

// UpdateRequestStatus changes the stored lifecycle status for a request.
func (s *InMemoryApprovalStore) UpdateRequestStatus(approvalRequestID string, status ApprovalStatus) (ApprovalRequest, bool) {
	if s == nil {
		return ApprovalRequest{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[approvalRequestID]
	if !ok {
		return ApprovalRequest{}, false
	}
	record.request.Status = status
	return record.request, true
}

// AppendEntry appends a digest-linked entry to a request.
func (s *InMemoryApprovalStore) AppendEntry(entry ApprovalChainEntry) error {
	if s == nil {
		return ErrApprovalRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[entry.ApprovalRequestID]
	if !ok {
		return ErrApprovalRequestNotFound
	}
	record.entries = append(record.entries, cloneApprovalChainEntry(entry))
	return nil
}

// ListEntries returns a copy of request entries in append order.
func (s *InMemoryApprovalStore) ListEntries(approvalRequestID string) ([]ApprovalChainEntry, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[approvalRequestID]
	if !ok {
		return nil, false
	}
	return cloneApprovalChainEntries(record.entries), true
}

// SaveResolution stores or replaces the terminal resolution for a request.
func (s *InMemoryApprovalStore) SaveResolution(resolution ApprovalResolution) error {
	if s == nil {
		return ErrApprovalRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[resolution.ApprovalRequestID]
	if !ok {
		return ErrApprovalRequestNotFound
	}
	copied := resolution
	record.resolution = &copied
	return nil
}

// GetResolution returns the terminal resolution for a request, if any.
func (s *InMemoryApprovalStore) GetResolution(approvalRequestID string) (ApprovalResolution, bool) {
	if s == nil {
		return ApprovalResolution{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[approvalRequestID]
	if !ok || record.resolution == nil {
		return ApprovalResolution{}, false
	}
	return *record.resolution, true
}

// ConsumeApproval atomically marks an allowed approval as consumed.
func (s *InMemoryApprovalStore) ConsumeApproval(approvalRequestID string) (ApprovalRequest, bool) {
	if s == nil {
		return ApprovalRequest{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[approvalRequestID]
	if !ok || record.request.Status != ApprovalAllowed {
		if ok {
			return record.request, false
		}
		return ApprovalRequest{}, false
	}
	record.request.Status = ApprovalConsumed
	return record.request, true
}

func (s *InMemoryApprovalStore) ensureRecordsLocked() {
	if s.records == nil {
		s.records = make(map[string]*approvalStoreRecord)
	}
}

func cloneApprovalChainEntries(entries []ApprovalChainEntry) []ApprovalChainEntry {
	if len(entries) == 0 {
		return nil
	}
	cloned := make([]ApprovalChainEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = cloneApprovalChainEntry(entry)
	}
	return cloned
}

func cloneApprovalChainEntry(entry ApprovalChainEntry) ApprovalChainEntry {
	entry.Roles = cloneStrings(entry.Roles)
	return entry
}
