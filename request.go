package caddysamldisco

import (
	"sync"
	"time"
)

// RequestStore tracks SAML AuthnRequest IDs to prevent replay attacks.
// Implementations must be safe for concurrent use.
type RequestStore interface {
	// Store saves a request ID with its expiry time.
	Store(requestID string, expiry time.Time) error

	// Valid checks if a request ID exists and is not expired.
	// Returns true only once per ID (single-use).
	Valid(requestID string) bool

	// GetAll returns all non-expired request IDs.
	// Used by crewjam/saml for InResponseTo validation.
	GetAll() []string
}

// InMemoryRequestStore is an in-memory implementation of RequestStore.
// Safe for concurrent use.
type InMemoryRequestStore struct {
	mu        sync.RWMutex
	entries   map[string]time.Time
	stopCh    chan struct{}
	closed    bool
	onCleanup func() // callback after each cleanup cycle (for testing)
}

// RequestStoreOption is a functional option for configuring request stores.
type RequestStoreOption func(*InMemoryRequestStore)

// WithOnCleanup returns an option that sets a callback invoked after each cleanup cycle.
// Used for testing synchronization.
func WithOnCleanup(fn func()) RequestStoreOption {
	return func(s *InMemoryRequestStore) {
		s.onCleanup = fn
	}
}

// NewInMemoryRequestStore creates a new in-memory request store without background cleanup.
func NewInMemoryRequestStore() *InMemoryRequestStore {
	return &InMemoryRequestStore{
		entries: make(map[string]time.Time),
	}
}

// NewInMemoryRequestStoreWithCleanup creates a store with periodic background cleanup.
func NewInMemoryRequestStoreWithCleanup(cleanupInterval time.Duration, opts ...RequestStoreOption) *InMemoryRequestStore {
	s := &InMemoryRequestStore{
		entries: make(map[string]time.Time),
		stopCh:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	go s.cleanupLoop(cleanupInterval)
	return s
}

// cleanupLoop runs periodic cleanup of expired entries.
func (s *InMemoryRequestStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
			if s.onCleanup != nil {
				s.onCleanup()
			}
		case <-s.stopCh:
			return
		}
	}
}

// cleanup removes all expired entries.
func (s *InMemoryRequestStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, expiry := range s.entries {
		if now.After(expiry) {
			delete(s.entries, id)
		}
	}
}

// Close stops the background cleanup goroutine.
func (s *InMemoryRequestStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopCh != nil && !s.closed {
		close(s.stopCh)
		s.closed = true
	}
	return nil
}

// Store saves a request ID with its expiry time.
func (s *InMemoryRequestStore) Store(requestID string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[requestID] = expiry
	return nil
}

// Valid checks if a request ID exists and is not expired.
// Single-use: deletes the entry after successful validation.
func (s *InMemoryRequestStore) Valid(requestID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.entries[requestID]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
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
	for id, expiry := range s.entries {
		if now.Before(expiry) {
			ids = append(ids, id)
		}
	}
	return ids
}
