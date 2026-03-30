//go:build unit

package request

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// SimTest1: Single-use enforcement under concurrency.
// 10 goroutines simultaneously call Valid() on the same request ID.
// Exactly one must return true; the rest must return false.
func TestSim_SingleUseUnderConcurrency(t *testing.T) {
	tra.Require(t, "Adapter.Request.SingleUseUnderConcurrency")
	store := NewInMemoryRequestStore()
	if err := store.Store("req-X", time.Now().Add(5*time.Second)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	const n = 10
	var barrier sync.WaitGroup
	barrier.Add(1) // released once all goroutines are ready

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
			if store.Valid("req-X") {
				trueCount.Add(1)
			}
		}()
	}

	ready.Wait()  // all goroutines are parked at barrier
	barrier.Done() // release all at once
	done.Wait()

	if got := trueCount.Load(); got != 1 {
		t.Errorf("Valid() returned true %d times, want exactly 1", got)
	}
}

// SimTest2: Expiry enforcement via lazy check in Valid().
// Store a request with a TTL in the past; Valid() must return false.
func TestSim_ExpiryEnforcement(t *testing.T) {
	tra.Require(t, "Adapter.Request.ExpiryEnforcement")
	store := NewInMemoryRequestStore()

	// Store with expiry already in the past.
	if err := store.Store("req-expired", time.Now().Add(-10*time.Millisecond)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	if store.Valid("req-expired") {
		t.Error("Valid() returned true for an already-expired request ID, want false")
	}
}

// SimTest3: Cleanup vs Valid race.
// Verifies that the background cleanup goroutine removes expired entries
// without interfering with Valid() for live entries.
func TestSim_CleanupVsValidRace(t *testing.T) {
	tra.Require(t, "Adapter.Request.CleanupVsValidRace")
	cleaned := make(chan struct{}, 10)
	store := NewInMemoryRequestStoreWithCleanup(
		20*time.Millisecond,
		WithOnCleanup(func() { cleaned <- struct{}{} }),
	)
	defer store.Close()

	// Store a live entry that should survive cleanup.
	if err := store.Store("req-live", time.Now().Add(10*time.Second)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Wait for the first cleanup cycle to complete.
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first cleanup cycle")
	}

	// Now store a short-lived entry that should be swept on the next cycle.
	if err := store.Store("req-short", time.Now().Add(-1*time.Millisecond)); err != nil {
		t.Fatalf("Store() error: %v", err)
	}

	// Wait for the second cleanup cycle.
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for second cleanup cycle")
	}

	// req-short was expired; it must not appear in GetAll().
	for _, id := range store.GetAll() {
		if id == "req-short" {
			t.Error("GetAll() still contains req-short after cleanup, want it removed")
		}
	}

	// req-live must still be present and valid.
	if !store.Valid("req-live") {
		t.Error("Valid() returned false for req-live, want true (entry should not have been cleaned up)")
	}
}

// SimTest4: Close during cleanup.
// Calls Close() while the cleanup goroutine may be running and verifies
// there is no deadlock and that Close() is idempotent.
func TestSim_CloseDuringCleanup(t *testing.T) {
	tra.Require(t, "Adapter.Request.CloseDuringCleanup")
	cleaned := make(chan struct{}, 10)
	store := NewInMemoryRequestStoreWithCleanup(
		10*time.Millisecond,
		WithOnCleanup(func() { cleaned <- struct{}{} }),
	)

	// Let at least one cleanup cycle run to confirm the goroutine is alive.
	select {
	case <-cleaned:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cleanup cycle before Close()")
	}

	// Close() must return without deadlocking.
	closeDone := make(chan error, 1)
	go func() { closeDone <- store.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("Close() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() deadlocked")
	}

	// Close() is idempotent — second call must not panic or error.
	if err := store.Close(); err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}
