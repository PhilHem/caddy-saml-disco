package entitlements

import (
	"context"
	"sync"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// InMemoryEntitlementStore is an in-memory implementation of EntitlementStore.
// Suitable for testing and development.
type InMemoryEntitlementStore struct {
	mu             sync.RWMutex
	defaultAction  domain.DefaultAction
	exactMatches   map[string]domain.Entitlement
	patternMatches []domain.Entitlement
}

// NewInMemoryEntitlementStore creates a new in-memory entitlement store.
func NewInMemoryEntitlementStore() *InMemoryEntitlementStore {
	return &InMemoryEntitlementStore{
		defaultAction: domain.DefaultActionDeny,
		exactMatches:  make(map[string]domain.Entitlement),
	}
}

// Add adds an entitlement to the store.
// This is a test helper method - production adapters load from files.
func (s *InMemoryEntitlementStore) Add(e domain.Entitlement) error {
	if err := e.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e.Subject != "" {
		s.exactMatches[e.Subject] = e
	} else if e.Pattern != "" {
		s.patternMatches = append(s.patternMatches, e)
	}

	return nil
}

// SetDefaultAction sets the default action for unmatched subjects.
func (s *InMemoryEntitlementStore) SetDefaultAction(action domain.DefaultAction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultAction = action
}

// Lookup returns entitlements for a subject.
func (s *InMemoryEntitlementStore) Lookup(subject string) (*domain.EntitlementResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check exact matches first
	if e, ok := s.exactMatches[subject]; ok {
		return &domain.EntitlementResult{
			Roles:    e.Roles,
			Metadata: e.Metadata,
			Matched:  true,
		}, nil
	}

	// Check pattern matches
	for _, e := range s.patternMatches {
		if domain.MatchesSubjectPattern(subject, e.Pattern) {
			return &domain.EntitlementResult{
				Roles:    e.Roles,
				Metadata: e.Metadata,
				Matched:  true,
			}, nil
		}
	}

	// No match - apply default action
	if s.defaultAction == domain.DefaultActionDeny {
		return nil, domain.ErrEntitlementNotFound
	}

	return &domain.EntitlementResult{Matched: false}, nil
}

// Refresh is a no-op for in-memory store.
func (s *InMemoryEntitlementStore) Refresh(ctx context.Context) error {
	return nil
}

// Ensure InMemoryEntitlementStore implements ports.EntitlementStore
var _ ports.EntitlementStore = (*InMemoryEntitlementStore)(nil)






