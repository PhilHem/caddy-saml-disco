package metadata

import (
	"context"
	"sync"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// InMemoryMetadataStore is a simple in-memory metadata store for testing.
type InMemoryMetadataStore struct {
	mu         sync.RWMutex
	idps       []domain.IdPInfo
	validUntil *time.Time
}

// NewInMemoryMetadataStore creates a new InMemoryMetadataStore with the given IdPs.
func NewInMemoryMetadataStore(idps []domain.IdPInfo) *InMemoryMetadataStore {
	return &InMemoryMetadataStore{idps: idps}
}

// NewInMemoryMetadataStoreWithValidUntil creates a new InMemoryMetadataStore with
// the given IdPs and a validUntil timestamp for testing.
func NewInMemoryMetadataStoreWithValidUntil(idps []domain.IdPInfo, validUntil *time.Time) *InMemoryMetadataStore {
	return &InMemoryMetadataStore{idps: idps, validUntil: validUntil}
}

// GetIdP returns the IdP with the given entity ID.
func (s *InMemoryMetadataStore) GetIdP(entityID string) (*domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.idps {
		if s.idps[i].EntityID == entityID {
			idp := s.idps[i]
			return &idp, nil
		}
	}
	return nil, domain.ErrIdPNotFound
}

// ListIdPs returns all IdPs, optionally filtered by a search term.
// Searches across EntityID, DisplayName, and all DisplayNames language variants.
func (s *InMemoryMetadataStore) ListIdPs(filter string) ([]domain.IdPInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []domain.IdPInfo
	for _, idp := range s.idps {
		if domain.MatchesSearch(&idp, filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

// Refresh is a no-op for in-memory store.
func (s *InMemoryMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

// Health returns the health status of the in-memory store.
// In-memory stores are always considered fresh.
func (s *InMemoryMetadataStore) Health() domain.MetadataHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return domain.MetadataHealth{
		IsFresh:            true,
		IdPCount:           len(s.idps),
		MetadataValidUntil: s.validUntil,
	}
}

// Ensure InMemoryMetadataStore implements ports.MetadataStore
var _ ports.MetadataStore = (*InMemoryMetadataStore)(nil)






