package logo

import (
	"github.com/philiph/caddy-saml-disco/internal/cache"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// DefaultLogoCapacity is the default maximum number of logos held in memory.
const DefaultLogoCapacity = 1000

// InMemoryLogoStore stores logos in memory with LRU eviction.
// Thread-safe: delegates all concurrency control to BoundedCache.
type InMemoryLogoStore struct {
	cache *cache.BoundedCache[string, *ports.CachedLogo]
}

// NewInMemoryLogoStore creates a new in-memory logo store with DefaultLogoCapacity.
func NewInMemoryLogoStore() *InMemoryLogoStore {
	return NewInMemoryLogoStoreWithCapacity(DefaultLogoCapacity)
}

// NewInMemoryLogoStoreWithCapacity creates a new in-memory logo store with the given capacity.
func NewInMemoryLogoStoreWithCapacity(capacity int) *InMemoryLogoStore {
	return &InMemoryLogoStore{
		cache: cache.NewBoundedCache[string, *ports.CachedLogo](capacity),
	}
}

// Get returns a cached logo by entity ID.
func (s *InMemoryLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	if logo, ok := s.cache.Get(entityID); ok {
		return logo, nil
	}
	return nil, ErrLogoNotFound
}

// Set stores a logo for the given entity ID.
func (s *InMemoryLogoStore) Set(entityID string, logo *ports.CachedLogo) {
	s.cache.Set(entityID, logo)
}

// Ensure InMemoryLogoStore implements ports.LogoStore
var _ ports.LogoStore = (*InMemoryLogoStore)(nil)
