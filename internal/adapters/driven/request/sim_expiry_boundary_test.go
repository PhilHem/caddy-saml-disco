//go:build unit

package request

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SimExpiry1: Request valid just before its expiry window closes.
// Stores a request with a 100ms TTL, waits 90ms, then checks Valid().
// The request must still be accepted — it has not yet expired.
func TestSimExpiry_ValidJustBeforeExpiry(t *testing.T) {
	store := NewInMemoryRequestStore()

	ttl := 100 * time.Millisecond
	if err := store.Store("req-boundary-early", time.Now().Add(ttl)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	time.Sleep(90 * time.Millisecond)

	if !store.Valid("req-boundary-early") {
		t.Error("Valid() returned false at 90ms of a 100ms TTL, want true (not yet expired)")
	}
}

// SimExpiry2: Request invalid just after its expiry window closes.
// Stores a request with a 100ms TTL, waits 110ms, then checks Valid().
// The lazy expiry check in Valid() must reject the entry.
func TestSimExpiry_InvalidJustAfterExpiry(t *testing.T) {
	store := NewInMemoryRequestStore()

	ttl := 100 * time.Millisecond
	if err := store.Store("req-boundary-late", time.Now().Add(ttl)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	time.Sleep(110 * time.Millisecond)

	if store.Valid("req-boundary-late") {
		t.Error("Valid() returned true at 110ms of a 100ms TTL, want false (expired)")
	}
}

// SimExpiry3: Cleanup evicts an expired entry before Valid is called.
// Creates a store with background cleanup, stores a request with a 50ms TTL,
// waits for expiry and at least one cleanup cycle, then verifies the entry is gone
// from both GetAll() and Valid().
func TestSimExpiry_CleanupEvictsBeforeValid(t *testing.T) {
	cleaned := make(chan struct{}, 10)
	store := NewInMemoryRequestStoreWithCleanup(
		30*time.Millisecond,
		WithOnCleanup(func() { cleaned <- struct{}{} }),
	)
	defer store.Close()

	ttl := 50 * time.Millisecond
	if err := store.Store("req-evict", time.Now().Add(ttl)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Wait for the TTL to elapse before the cleanup cycle runs.
	time.Sleep(60 * time.Millisecond)

	// Wait for cleanup to run and confirm eviction.
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cleanup cycle")
	}

	// GetAll() must not include the expired entry.
	for _, id := range store.GetAll() {
		if id == "req-evict" {
			t.Error("GetAll() still contains req-evict after cleanup, want it evicted")
		}
	}

	// Valid() must return false — the entry no longer exists.
	if store.Valid("req-evict") {
		t.Error("Valid() returned true for req-evict after cleanup evicted it, want false")
	}
}

// SimExpiry4: Concurrent Valid() calls at the expiry boundary.
// Stores a request with a 200ms TTL, waits 195ms (just before expiry),
// then launches 10 goroutines calling Valid() simultaneously.
// At most 1 goroutine may receive true (single-use guarantee).
// No panics or data races are permitted.
func TestSimExpiry_ConcurrentValidAtBoundary(t *testing.T) {
	store := NewInMemoryRequestStore()

	ttl := 200 * time.Millisecond
	if err := store.Store("req-concurrent-boundary", time.Now().Add(ttl)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	time.Sleep(195 * time.Millisecond)

	const n = 10
	var barrier sync.WaitGroup
	barrier.Add(1)

	var ready sync.WaitGroup
	ready.Add(n)

	var trueCount atomic.Int64
	var done sync.WaitGroup
	done.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			ready.Done()   // signal ready
			barrier.Wait() // wait for start gun
			if store.Valid("req-concurrent-boundary") {
				trueCount.Add(1)
			}
		}()
	}

	ready.Wait()   // all goroutines parked at barrier
	barrier.Done() // release all at once
	done.Wait()

	// At most one goroutine may win (single-use); zero is also valid
	// when the 5ms window races past expiry.
	if got := trueCount.Load(); got > 1 {
		t.Errorf("Valid() returned true %d times, want at most 1 (single-use guarantee)", got)
	}
}
