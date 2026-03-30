package caddy

import (
	"sync"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/request"
	"github.com/philiph/caddy-saml-disco/internal/ports"
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

// Close is a no-op to prevent closing the shared store.
func (n *nonClosingStore) Close() error {
	return nil
}

// getSharedRequestStore returns a singleton request store that persists across
// config reloads. This ensures in-flight SAML request IDs (from AuthnRequest to
// ACS response) are not lost when Caddy reloads its configuration.
//
// The returned store is wrapped to prevent Close() from actually closing it,
// protecting the shared store from being shut down during config reloads.
func getSharedRequestStore() ports.RequestStore {
	sharedRequestStoreOnce.Do(func() {
		// Create request store with background cleanup
		// This store lives for the entire Caddy process lifetime
		underlying := request.NewInMemoryRequestStoreWithCleanup(
			DefaultRequestCleanupInterval,
		)
		// Wrap it to prevent Close() from shutting it down
		sharedRequestStore = &nonClosingStore{store: underlying}
	})
	return sharedRequestStore
}
