package metadata

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// metadataSnapshot holds an immutable point-in-time view of the IdP set.
// Once created it is never mutated; Replace() installs a new snapshot atomically.
type metadataSnapshot struct {
	idps       []domain.IdPInfo
	byID       map[string]*domain.IdPInfo
	validUntil *time.Time
}

// newSnapshot builds a snapshot with a pre-computed entity-ID index.
func newSnapshot(idps []domain.IdPInfo, validUntil *time.Time) *metadataSnapshot {
	byID := make(map[string]*domain.IdPInfo, len(idps))
	// Copy the slice so the snapshot owns its data independently of the caller.
	copied := make([]domain.IdPInfo, len(idps))
	copy(copied, idps)
	for i := range copied {
		byID[copied[i].EntityID] = &copied[i]
	}
	return &metadataSnapshot{
		idps:       copied,
		byID:       byID,
		validUntil: validUntil,
	}
}

// InMemoryMetadataStore is a simple in-memory metadata store for testing.
type InMemoryMetadataStore struct {
	data atomic.Pointer[metadataSnapshot]
}

// NewInMemoryMetadataStore creates a new InMemoryMetadataStore with the given IdPs.
func NewInMemoryMetadataStore(idps []domain.IdPInfo) *InMemoryMetadataStore {
	s := &InMemoryMetadataStore{}
	s.data.Store(newSnapshot(idps, nil))
	return s
}

// NewInMemoryMetadataStoreWithValidUntil creates a new InMemoryMetadataStore with
// the given IdPs and a validUntil timestamp for testing.
func NewInMemoryMetadataStoreWithValidUntil(idps []domain.IdPInfo, validUntil *time.Time) *InMemoryMetadataStore {
	s := &InMemoryMetadataStore{}
	s.data.Store(newSnapshot(idps, validUntil))
	return s
}

// GetIdP returns the IdP with the given entity ID.
func (s *InMemoryMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	snap := s.data.Load()
	if idp, ok := snap.byID[entityID]; ok {
		// Return a copy so callers cannot mutate snapshot internals.
		result := *idp
		return &result, nil
	}
	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
// Always returns an empty slice (not nil) when no IdPs match.
func (s *InMemoryMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	snap := s.data.Load()
	result := make([]domain.IdPInfo, 0)
	for _, idp := range snap.idps {
		idp := idp // local copy for pointer stability inside MatchesSearch
		if domain.MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

// Replace atomically swaps the full IdP list with the provided slice.
// This is used in tests to simulate a metadata refresh without constructing
// a new store instance.
func (s *InMemoryMetadataStore) Replace(idps []domain.IdPInfo) {
	s.data.Store(newSnapshot(idps, nil))
}

// Refresh is a no-op for in-memory store.
func (s *InMemoryMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

// Health returns the health status of the in-memory store.
// In-memory stores are always considered fresh.
func (s *InMemoryMetadataStore) Health() domain.MetadataHealth {
	snap := s.data.Load()
	return domain.MetadataHealth{
		IsFresh:            true,
		IdPCount:           len(snap.idps),
		MetadataValidUntil: snap.validUntil,
	}
}

// Ensure InMemoryMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*InMemoryMetadataStore)(nil)
