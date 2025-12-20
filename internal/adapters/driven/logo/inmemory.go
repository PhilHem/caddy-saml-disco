package logo

import (
	"sync"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// InMemoryLogoStore stores logos in memory. Thread-safe.
type InMemoryLogoStore struct {
	mu    sync.RWMutex
	logos map[string]*ports.CachedLogo
}

// NewInMemoryLogoStore creates a new in-memory logo store.
func NewInMemoryLogoStore() *InMemoryLogoStore {
	return &InMemoryLogoStore{logos: make(map[string]*ports.CachedLogo)}
}

// Get returns a cached logo by entity ID.
func (s *InMemoryLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if logo, ok := s.logos[entityID]; ok {
		return logo, nil
	}
	return nil, ErrLogoNotFound
}

// Set stores a logo for the given entity ID.
func (s *InMemoryLogoStore) Set(entityID string, logo *ports.CachedLogo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logos[entityID] = logo
}

// Ensure InMemoryLogoStore implements ports.LogoStore
var _ ports.LogoStore = (*InMemoryLogoStore)(nil)






