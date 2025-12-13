//go:build unit

package caddysamldisco

import (
	"testing"
	"time"
)

// Cycle 1: Verify RequestStore interface exists with required methods
func TestRequestStore_Interface(t *testing.T) {
	// This test verifies the interface contract exists
	var _ RequestStore = (*mockRequestStore)(nil)
}

// mockRequestStore is a minimal implementation for interface verification
type mockRequestStore struct{}

func (m *mockRequestStore) Store(requestID string, expiry time.Time) error {
	return nil
}

func (m *mockRequestStore) Valid(requestID string) bool {
	return false
}

func (m *mockRequestStore) GetAll() []string {
	return nil
}

// Cycle 2: Verify InMemoryRequestStore implements interface and Store works
func TestInMemoryRequestStore_Interface(t *testing.T) {
	var _ RequestStore = (*InMemoryRequestStore)(nil)
}

func TestInMemoryRequestStore_Store(t *testing.T) {
	store := NewInMemoryRequestStore()

	err := store.Store("req-123", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("Store() returned error: %v", err)
	}

	// Verify it was stored by checking GetAll includes it
	ids := store.GetAll()
	if len(ids) != 1 || ids[0] != "req-123" {
		t.Errorf("GetAll() = %v, want [req-123]", ids)
	}
}

// Cycle 3: Valid returns true for stored, non-expired ID
func TestInMemoryRequestStore_Valid_Found(t *testing.T) {
	store := NewInMemoryRequestStore()
	store.Store("req-123", time.Now().Add(5*time.Minute))

	if !store.Valid("req-123") {
		t.Error("Valid() = false, want true for stored ID")
	}
}

func TestInMemoryRequestStore_Valid_NotFound(t *testing.T) {
	store := NewInMemoryRequestStore()

	if store.Valid("unknown") {
		t.Error("Valid() = true, want false for unknown ID")
	}
}

// Cycle 4: Valid is single-use (returns false on second call)
func TestInMemoryRequestStore_Valid_SingleUse(t *testing.T) {
	store := NewInMemoryRequestStore()
	store.Store("req-123", time.Now().Add(5*time.Minute))

	// First call should return true
	if !store.Valid("req-123") {
		t.Fatal("Valid() first call = false, want true")
	}

	// Second call should return false (consumed)
	if store.Valid("req-123") {
		t.Error("Valid() second call = true, want false (should be consumed)")
	}
}

// Cycle 5: Valid returns false for expired ID
func TestInMemoryRequestStore_Valid_Expired(t *testing.T) {
	store := NewInMemoryRequestStore()
	// Store with expiry in the past
	store.Store("req-expired", time.Now().Add(-1*time.Second))

	if store.Valid("req-expired") {
		t.Error("Valid() = true, want false for expired ID")
	}
}

// Cycle 6: GetAll excludes expired IDs
func TestInMemoryRequestStore_GetAll_FilterExpired(t *testing.T) {
	store := NewInMemoryRequestStore()
	store.Store("valid-1", time.Now().Add(5*time.Minute))
	store.Store("expired-1", time.Now().Add(-1*time.Second))
	store.Store("valid-2", time.Now().Add(10*time.Minute))

	ids := store.GetAll()

	// Should only contain valid IDs
	if len(ids) != 2 {
		t.Errorf("GetAll() returned %d IDs, want 2", len(ids))
	}

	// Check valid IDs are present
	found := make(map[string]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found["valid-1"] || !found["valid-2"] {
		t.Errorf("GetAll() = %v, want [valid-1, valid-2]", ids)
	}
	if found["expired-1"] {
		t.Error("GetAll() included expired-1, should be filtered")
	}
}

// Cycle 7: Thread safety - concurrent access should not race
func TestInMemoryRequestStore_Concurrent(t *testing.T) {
	store := NewInMemoryRequestStore()
	done := make(chan bool)

	// Concurrent stores
	go func() {
		for i := 0; i < 100; i++ {
			store.Store("req-a-"+string(rune(i)), time.Now().Add(5*time.Minute))
		}
		done <- true
	}()

	// Concurrent valid checks
	go func() {
		for i := 0; i < 100; i++ {
			store.Valid("req-b-" + string(rune(i)))
		}
		done <- true
	}()

	// Concurrent getall
	go func() {
		for i := 0; i < 100; i++ {
			store.GetAll()
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}

// Cycle 8: Background cleanup purges expired entries
func TestInMemoryRequestStore_BackgroundCleanup(t *testing.T) {
	// Create store with 50ms cleanup interval
	store := NewInMemoryRequestStoreWithCleanup(50 * time.Millisecond)
	defer store.Close()

	// Store an entry that expires immediately
	store.Store("expired", time.Now().Add(-1*time.Second))
	// Store an entry that won't expire
	store.Store("valid", time.Now().Add(10*time.Minute))

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Check that expired entry was purged by looking at internal state
	store.mu.RLock()
	_, expiredExists := store.entries["expired"]
	_, validExists := store.entries["valid"]
	store.mu.RUnlock()

	if expiredExists {
		t.Error("expired entry still exists after cleanup")
	}
	if !validExists {
		t.Error("valid entry was incorrectly purged")
	}
}

func TestInMemoryRequestStore_Close(t *testing.T) {
	store := NewInMemoryRequestStoreWithCleanup(50 * time.Millisecond)

	err := store.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Calling Close again should be safe
	err = store.Close()
	if err != nil {
		t.Errorf("Close() second call returned error: %v", err)
	}
}
