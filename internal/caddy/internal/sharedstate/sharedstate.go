// Package sharedstate manages process-lifetime singletons shared across Caddy
// config reloads. Only importable by packages rooted at internal/caddy/.
package sharedstate

import (
	"sync"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/request"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

var (
	// Protect shared request store initialization with sync.Once to ensure only one
	// store is created across all config reloads. This allows in-flight SAML flows
	// to survive Caddy config reloads.
	sharedRequestStoreOnce sync.Once
	sharedRequestStore     ports.RequestStore
)

// nonClosingStore wraps a RequestStore and prevents Close() from closing it.
// Used to protect the shared request store from being closed during config reloads.
type nonClosingStore struct {
	store ports.RequestStore
}

// Store delegates to the underlying store.
func (n *nonClosingStore) Store(requestID string, expiry time.Time) error {
	return n.store.Store(requestID, expiry)
}

// Valid delegates to the underlying store.
func (n *nonClosingStore) Valid(requestID string) bool {
	return n.store.Valid(requestID)
}

// GetAll delegates to the underlying store.
func (n *nonClosingStore) GetAll() []string {
	return n.store.GetAll()
}

// StoreWithEntityID forwards to the underlying store if it supports the extended
// interface, otherwise falls back to plain Store without recording the entity ID.
func (n *nonClosingStore) StoreWithEntityID(id string, expiry time.Time, entityID string) {
	if store, ok := n.store.(interface {
		StoreWithEntityID(string, time.Time, string)
	}); ok {
		store.StoreWithEntityID(id, expiry, entityID)
	} else {
		n.store.Store(id, expiry) //nolint:errcheck
	}
}

// GetEntityID forwards to the underlying store if it supports the extended
// interface, otherwise returns ("", false).
func (n *nonClosingStore) GetEntityID(id string) (string, bool) {
	if store, ok := n.store.(interface {
		GetEntityID(string) (string, bool)
	}); ok {
		return store.GetEntityID(id)
	}
	return "", false
}

// Close is a no-op to prevent closing the shared store.
func (n *nonClosingStore) Close() error {
	return nil
}

// GetSharedRequestStore returns a singleton request store that persists across
// config reloads. This ensures in-flight SAML request IDs (from AuthnRequest to
// ACS response) are not lost when Caddy reloads its configuration.
//
// The returned store is wrapped to prevent Close() from actually closing it,
// protecting the shared store from being shut down during config reloads.
func GetSharedRequestStore() ports.RequestStore {
	sharedRequestStoreOnce.Do(func() {
		// Create request store with background cleanup.
		// This store lives for the entire Caddy process lifetime.
		underlying := request.NewInMemoryRequestStoreWithCleanup(
			samlsvc.DefaultRequestCleanupInterval,
		)
		// Wrap it to prevent Close() from shutting it down.
		sharedRequestStore = &nonClosingStore{store: underlying}
	})
	return sharedRequestStore
}
