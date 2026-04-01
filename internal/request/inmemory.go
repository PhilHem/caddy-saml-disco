package request

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/worker"
)

// requestEntry holds the expiry time and optional IdP entity ID for a pending SAML request.
type requestEntry struct {
	expiry   time.Time
	entityID string
}

// InMemoryRequestStore is an in-memory implementation of RequestStore.
// Safe for concurrent use.
type InMemoryRequestStore struct {
	mu      sync.RWMutex
	entries map[string]requestEntry
	worker  *worker.SupervisedWorker
}

// RequestStoreOption is a functional option for configuring request stores.
type RequestStoreOption func(*inMemoryRequestStoreConfig)

// inMemoryRequestStoreConfig holds options applied before the store is created.
type inMemoryRequestStoreConfig struct {
	onCleanup func()
}

// WithOnCleanup returns an option that sets a callback invoked after each cleanup cycle.
// Used for testing synchronization.
func WithOnCleanup(fn func()) RequestStoreOption {
	return func(cfg *inMemoryRequestStoreConfig) {
		cfg.onCleanup = fn
	}
}

// NewInMemoryRequestStore creates a new in-memory request store without background cleanup.
func NewInMemoryRequestStore() *InMemoryRequestStore {
	return &InMemoryRequestStore{
		entries: make(map[string]requestEntry),
	}
}

// NewInMemoryRequestStoreWithCleanup creates a store with periodic background cleanup.
func NewInMemoryRequestStoreWithCleanup(cleanupInterval time.Duration, opts ...RequestStoreOption) *InMemoryRequestStore {
	cfg := &inMemoryRequestStoreConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	s := &InMemoryRequestStore{
		entries: make(map[string]requestEntry),
	}

	workerOpts := []worker.Option{}
	if cfg.onCleanup != nil {
		onCleanup := cfg.onCleanup
		workerOpts = append(workerOpts, worker.WithOnTick(func(_ error) {
			onCleanup()
		}))
	}

	w := worker.NewSupervisedWorker(
		"request-cleanup",
		cleanupInterval,
		func(_ context.Context) error {
			s.cleanup()
			return nil
		},
		zap.NewNop(),
		workerOpts...,
	)
	w.Start()
	s.worker = w

	return s
}

// cleanup removes all expired entries.
func (s *InMemoryRequestStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, entry := range s.entries {
		if now.After(entry.expiry) {
			delete(s.entries, id)
		}
	}
}

// Close stops the background cleanup goroutine.
func (s *InMemoryRequestStore) Close() error {
	if s.worker != nil {
		s.worker.Close()
	}
	return nil
}

// Store saves a request ID with its expiry time.
func (s *InMemoryRequestStore) Store(requestID string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[requestID] = requestEntry{expiry: expiry}
	return nil
}

// StoreWithEntityID saves a request ID with its expiry time and the IdP entity ID
// that was targeted by the AuthnRequest. This allows ACS to recover the IdP after
// a metadata refresh that changes entity IDs.
func (s *InMemoryRequestStore) StoreWithEntityID(requestID string, expiry time.Time, entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[requestID] = requestEntry{expiry: expiry, entityID: entityID}
}

// GetEntityID returns the IdP entity ID associated with the given request ID.
// Returns ("", false) if the request ID does not exist or has expired.
// This is a non-destructive read — the entry is not deleted.
func (s *InMemoryRequestStore) GetEntityID(requestID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[requestID]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiry) {
		return "", false
	}
	return entry.entityID, true
}

// Valid checks if a request ID exists and is not expired.
// Single-use: deletes the entry after successful validation.
func (s *InMemoryRequestStore) Valid(requestID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[requestID]
	if !ok {
		return false
	}
	if time.Now().After(entry.expiry) {
		delete(s.entries, requestID)
		return false
	}
	delete(s.entries, requestID)
	return true
}

// GetAll returns all non-expired request IDs.
func (s *InMemoryRequestStore) GetAll() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var ids []string
	for id, entry := range s.entries {
		if now.Before(entry.expiry) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Ensure InMemoryRequestStore implements ports.RequestStore
var _ ports.RequestStore = (*InMemoryRequestStore)(nil)
