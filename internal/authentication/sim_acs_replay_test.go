//go:build unit

package authentication

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/request"
)

// SimACSReplay verifies that the request store enforces single-use request IDs
// under concurrent access, mirroring the replay-prevention logic in HandleACS.
//
// Two goroutines race to consume the same request ID. Exactly one must succeed
// and exactly one must fail — the same invariant that HandleACS now enforces.
func TestSimACSReplay(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		store := request.NewInMemoryRequestStore()

		requestID := "test-request-id-12345"
		store.Store(requestID, time.Now().Add(10*time.Minute))

		var ready, done sync.WaitGroup
		var start sync.WaitGroup
		ready.Add(2)
		done.Add(2)
		start.Add(1)

		var successes atomic.Int32

		for g := 0; g < 2; g++ {
			go func() {
				defer done.Done()
				ready.Done()
				start.Wait()
				if store.Valid(requestID) {
					successes.Add(1)
				}
			}()
		}

		ready.Wait()
		start.Done()
		done.Wait()

		if s := successes.Load(); s != 1 {
			t.Fatalf("iteration %d: want exactly 1 success, got %d", i, s)
		}
	}
}
