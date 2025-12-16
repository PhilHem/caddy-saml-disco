//go:build unit

package caddysamldisco

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"testing/quick"
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
	// Use channel to synchronize on cleanup completion
	cleaned := make(chan struct{}, 10)
	store := NewInMemoryRequestStoreWithCleanup(50*time.Millisecond,
		WithOnCleanup(func() { cleaned <- struct{}{} }))
	defer store.Close()

	// Store an entry that expires immediately
	store.Store("expired", time.Now().Add(-1*time.Second))
	// Store an entry that won't expire
	store.Store("valid", time.Now().Add(10*time.Minute))

	// Wait for cleanup to run (use channel instead of time.Sleep)
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cleanup")
	}

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

// =============================================================================
// Property-Based Tests
// =============================================================================

// Property-based tests verify security-critical invariants of InMemoryRequestStore
// through systematic exploration of the state space. These tests complement
// example-based tests by checking properties hold across all possible inputs.
//
// Bugs Found Through Property-Based Testing:
// - None discovered. The implementation correctly enforces single-use through
//   exclusive locking (Lock() in Valid()), preventing race conditions where
//   multiple goroutines could validate the same ID simultaneously.
//
// Potential Edge Cases Analyzed:
// - Time precision: If expiry == time.Now(), time.Now().After(expiry) returns
//   false, so the ID is considered valid. This is acceptable behavior (ID valid
//   until exact expiry time) but worth noting for time-sensitive scenarios.
// - GetAll() consistency: Uses RLock() which is correct for read-only access.
//   The property test verifies that GetAll() only returns non-expired IDs.

// =============================================================================
// Invariant Checker Helpers
// =============================================================================

// checkSingleUseInvariant verifies that Valid() returns true at most once per ID.
func checkSingleUseInvariant(store *InMemoryRequestStore, requestID string) bool {
	trueCount := 0
	for i := 0; i < 10; i++ {
		if store.Valid(requestID) {
			trueCount++
		}
	}
	return trueCount <= 1
}

// checkExpiryInvariant verifies that expired IDs always return false from Valid().
func checkExpiryInvariant(store *InMemoryRequestStore, requestID string, expiry time.Time) bool {
	if time.Now().After(expiry) {
		return !store.Valid(requestID)
	}
	return true // Skip non-expired cases
}

// checkReplayPreventionInvariant verifies replay attack prevention:
// after Valid() returns true, subsequent calls return false.
func checkReplayPreventionInvariant(store *InMemoryRequestStore, requestID string) bool {
	firstResult := store.Valid(requestID)
	secondResult := store.Valid(requestID)

	// Property: If first was true, second must be false (single-use)
	if firstResult {
		return !secondResult
	}

	// If first was false (expired/not found), second should also be false
	return !secondResult
}

// checkGetAllConsistencyInvariant verifies that GetAll() only returns IDs that would pass Valid().
func checkGetAllConsistencyInvariant(store *InMemoryRequestStore, expectedValid map[string]bool) bool {
	allIDs := store.GetAll()

	for _, id := range allIDs {
		if !expectedValid[id] {
			return false // GetAll() returned an expired ID
		}
	}

	// Verify count matches expected (allowing for timing edge cases)
	expectedCount := len(expectedValid)
	validCount := len(allIDs)
	if validCount > expectedCount {
		return false // More IDs returned than expected
	}

	return true
}

// Cycle 9: Property-Based Test - Single-Use Enforcement
// Property: Valid() returns true at most once per ID
func TestInMemoryRequestStore_Property_SingleUse(t *testing.T) {
	f := func(requestID string, expiryOffset int64) bool {
		// Skip empty IDs
		if requestID == "" {
			return true
		}

		store := NewInMemoryRequestStore()
		expiry := time.Now().Add(time.Duration(expiryOffset) * time.Second)

		// Store the ID
		store.Store(requestID, expiry)

		// Use helper to check invariant
		return checkSingleUseInvariant(store, requestID)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 10: Property-Based Test - Expiry Validation
// Property: Expired IDs always return false from Valid()
func TestInMemoryRequestStore_Property_Expiry(t *testing.T) {
	f := func(requestID string, expiryOffset int64) bool {
		if requestID == "" {
			return true
		}

		store := NewInMemoryRequestStore()
		// Use offset to create expired or non-expired entries
		expiry := time.Now().Add(time.Duration(expiryOffset) * time.Second)

		store.Store(requestID, expiry)

		// Small delay to ensure expiry if offset was negative
		if expiryOffset < 0 {
			time.Sleep(10 * time.Millisecond)
		}

		// Use helper to check invariant
		return checkExpiryInvariant(store, requestID, expiry)
	}

	// Custom generator to bias towards expired entries for better coverage
	config := &quick.Config{
		Values: func(values []reflect.Value, r *rand.Rand) {
			// Generate random request ID
			idLen := r.Intn(20) + 1
			idBytes := make([]byte, idLen)
			for i := range idBytes {
				idBytes[i] = byte(r.Intn(26) + 'a')
			}
			values[0] = reflect.ValueOf(string(idBytes))

			// Generate mostly negative offsets (expired) with some positive
			offset := r.Int63n(200) - 150 // Range: -150 to 50 seconds
			values[1] = reflect.ValueOf(offset)
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}

// Cycle 11: Property-Based Test - Replay Attack Prevention
// Property: After Valid() returns true, subsequent calls return false (replay prevention)
func TestInMemoryRequestStore_Property_ReplayPrevention(t *testing.T) {
	f := func(requestID string, expiryOffset int64, waitOffset int64) bool {
		if requestID == "" {
			return true
		}

		store := NewInMemoryRequestStore()
		expiry := time.Now().Add(time.Duration(expiryOffset) * time.Second)

		store.Store(requestID, expiry)

		// Simulate waiting (for time-based tests)
		if waitOffset > 0 {
			time.Sleep(time.Duration(waitOffset) * time.Millisecond)
		}

		// Use helper to check invariant
		return checkReplayPreventionInvariant(store, requestID)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 12: Property-Based Test - GetAll Consistency
// Property: GetAll() only returns IDs that would pass Valid()
func TestInMemoryRequestStore_Property_GetAllConsistency(t *testing.T) {
	f := func(numIDs int, expiryOffsets []int64) bool {
		if numIDs < 0 || numIDs > 100 || len(expiryOffsets) == 0 {
			return true // Skip unreasonable sizes
		}

		store := NewInMemoryRequestStore()
		now := time.Now()

		// Store multiple IDs with various expiry times
		expectedValid := make(map[string]bool)
		for i := 0; i < numIDs; i++ {
			id := fmt.Sprintf("req-%d", i)
			offset := expiryOffsets[i%len(expiryOffsets)]
			expiry := now.Add(time.Duration(offset) * time.Second)
			store.Store(id, expiry)

			// Track which IDs should be valid (non-expired)
			if now.Before(expiry) {
				expectedValid[id] = true
			}
		}

		// Use helper to check invariant
		return checkGetAllConsistencyInvariant(store, expectedValid)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 13: Property-Based Test - Concurrent Access Invariants
// Property: Single-use and expiry invariants hold under concurrent access
func TestInMemoryRequestStore_Property_ConcurrentInvariants(t *testing.T) {
	f := func(requestID string, expiryOffset int64, numGoroutines int) bool {
		if requestID == "" || numGoroutines < 1 || numGoroutines > 10 {
			return true
		}

		store := NewInMemoryRequestStore()
		expiry := time.Now().Add(time.Duration(expiryOffset) * time.Second)
		store.Store(requestID, expiry)

		var wg sync.WaitGroup
		results := make(chan bool, numGoroutines)

		// Concurrent Valid() calls
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- store.Valid(requestID)
			}()
		}

		wg.Wait()
		close(results)

		// Count true results
		trueCount := 0
		for result := range results {
			if result {
				trueCount++
			}
		}

		// Property: At most one goroutine should get true (single-use)
		return trueCount <= 1
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
