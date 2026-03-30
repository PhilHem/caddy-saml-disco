package logo

import (
	"sync/atomic"

	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// logoSnapshot is an immutable point-in-time view of the logo cache.
type logoSnapshot struct {
	logos map[string]*ports.CachedLogo
}

// InMemoryLogoStore stores logos in memory. Thread-safe via copy-on-write.
type InMemoryLogoStore struct {
	data atomic.Pointer[logoSnapshot]
}

// NewInMemoryLogoStore creates a new in-memory logo store.
func NewInMemoryLogoStore() *InMemoryLogoStore {
	s := &InMemoryLogoStore{}
	s.data.Store(&logoSnapshot{logos: make(map[string]*ports.CachedLogo)})
	return s
}

// Get returns a cached logo by entity ID.
func (s *InMemoryLogoStore) Get(entityID string) (*ports.CachedLogo, error) {
	snap := s.data.Load()
	if logo, ok := snap.logos[entityID]; ok {
		return logo, nil
	}
	return nil, ErrLogoNotFound
}

// Set stores a logo for the given entity ID using copy-on-write.
func (s *InMemoryLogoStore) Set(entityID string, logo *ports.CachedLogo) {
	for {
		old := s.data.Load()
		newLogos := make(map[string]*ports.CachedLogo, len(old.logos)+1)
		for k, v := range old.logos {
			newLogos[k] = v
		}
		newLogos[entityID] = logo
		if s.data.CompareAndSwap(old, &logoSnapshot{logos: newLogos}) {
			return
		}
	}
}

// Ensure InMemoryLogoStore implements ports.LogoStore
var _ ports.LogoStore = (*InMemoryLogoStore)(nil)
