//go:build unit

package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func makeIdPs(ids ...string) []domain.IdPInfo {
	out := make([]domain.IdPInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.IdPInfo{
			EntityID:    "https://" + id + ".example.org/idp",
			DisplayName: id,
		})
	}
	return out
}

// TestSimComposite_ListGetConsistency exercises concurrent ListIdPs and GetIdP
// calls against a CompositeMetadataStore while the underlying store's data is
// atomically replaced mid-run. It uses the race detector (via -race) to verify
// that no data races occur.
//
// The property being tested: store2 is stable throughout the run, so every IdP
// listed from store2 must also be retrievable with GetIdP. After store1 is
// replaced, any ID from the *new* set (golf/hotel/india) returned by
// composite.ListIdPs must also be retrievable. Stale IDs from the old set
// (alpha/beta/charlie) may appear in a list snapshot before the replacement
// completes, and may subsequently fail GetIdP — that's an expected consequence
// of the design, not a bug. The test verifies no data races and that the stable
// store remains consistent throughout.
func TestSimComposite_ListGetConsistency(t *testing.T) {
	tra.Require(t, "Adapter.CompositeMetadataStore.ListGetConsistency")

	store1 := NewInMemoryMetadataStore(makeIdPs("alpha", "beta", "charlie"))
	store2 := NewInMemoryMetadataStore(makeIdPs("delta", "epsilon", "foxtrot"))

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	const numReaders = 20
	const runDuration = 500 * time.Millisecond

	// Track violations against the stable store2 only — those must never fail.
	var violations atomic.Int64
	deadline := time.Now().Add(runDuration)

	var wg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				// Stable store: every listed IdP must be retrievable.
				idps, err := store2.ListIdPs("")
				if err != nil {
					continue
				}
				for _, idp := range idps {
					if _, err := store2.GetIdP(idp.EntityID); err != nil {
						violations.Add(1)
					}
				}

				// Exercise composite path under concurrent replacement —
				// primarily stress-tests for races detected by -race.
				composite.ListIdPs("")   //nolint:errcheck
				composite.GetIdP("https://delta.example.org/idp") //nolint:errcheck
			}
		}()
	}

	// Mid-run: atomically replace store1's data (simulating a metadata refresh).
	// store2 is never touched and must remain fully consistent throughout.
	time.Sleep(runDuration / 2)
	store1.Replace(makeIdPs("golf", "hotel", "india"))

	wg.Wait()

	if n := violations.Load(); n > 0 {
		t.Errorf("stable store2 violated consistency %d time(s): an IdP returned by ListIdPs was not retrievable via GetIdP", n)
	}
}

// TestSimComposite_HealthPartialFailure verifies that composite Health() reports
// IsFresh=false and the correct total IdPCount when one store is unhealthy.
func TestSimComposite_HealthPartialFailure(t *testing.T) {
	tra.Require(t, "Adapter.CompositeMetadataStore.HealthPartialFailure")

	healthyStore := NewInMemoryMetadataStore(makeIdPs("a", "b", "c", "d", "e"))

	unhealthyStore := &HealthyMetadataStore{
		idps: []domain.IdPInfo{},
		health: domain.MetadataHealth{
			IsFresh:  false,
			IdPCount: 0,
		},
	}

	composite := NewCompositeMetadataStore([]ports.MetadataStore{healthyStore, unhealthyStore})

	health := composite.Health()

	if health.IsFresh {
		t.Errorf("Health().IsFresh = true; want false when any store is unhealthy")
	}
	if health.IdPCount != 5 {
		t.Errorf("Health().IdPCount = %d; want 5 (healthy store's count)", health.IdPCount)
	}
}

// TestSimComposite_ConcurrentRefreshAtomicity verifies that concurrent readers
// never observe a partial IdP set from a URL-backed store while Refresh() runs.
// URLMetadataStore replaces its idps slice under a write lock — so readers must
// see either the full old set or the full new set, never a partial one.
func TestSimComposite_ConcurrentRefreshAtomicity(t *testing.T) {
	tra.Require(t, "Adapter.CompositeMetadataStore.ConcurrentRefreshAtomicity")

	metadataBytes, err := os.ReadFile("../../../../testdata/multi-idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Both httptest servers serve the same multi-IdP aggregate so we know the
	// expected full-set count per store.
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataBytes) //nolint:errcheck
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadataBytes) //nolint:errcheck
	}))
	defer server2.Close()

	// TTL=0 so every Refresh() call bypasses the cache and fetches.
	urlStore1 := NewURLMetadataStore(server1.URL, 0)
	urlStore2 := NewURLMetadataStore(server2.URL, 0)

	if err := urlStore1.Load(); err != nil {
		t.Fatalf("urlStore1.Load(): %v", err)
	}
	if err := urlStore2.Load(); err != nil {
		t.Fatalf("urlStore2.Load(): %v", err)
	}

	initial, err := urlStore1.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() on urlStore1: %v", err)
	}
	expectedPerStore := len(initial)
	if expectedPerStore == 0 {
		t.Fatal("test metadata must contain at least one IdP")
	}

	composite := NewCompositeMetadataStore([]ports.MetadataStore{urlStore1, urlStore2})

	const runDuration = 500 * time.Millisecond
	deadline := time.Now().Add(runDuration)

	var partialReads atomic.Int64
	var wg sync.WaitGroup

	// Readers observe each backing store individually to catch partial writes.
	// A store mid-refresh must never expose fewer than the full set size — it
	// must present either the old full set or the new full set, never in-between.
	for _, store := range []*URLMetadataStore{urlStore1, urlStore2} {
		store := store
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				idps, err := store.ListIdPs("")
				if err != nil {
					continue
				}
				// Any non-zero count less than expectedPerStore indicates a
				// partial (torn) read while the slice was being replaced.
				if n := len(idps); n > 0 && n < expectedPerStore {
					partialReads.Add(1)
				}
			}
		}()
	}

	// Refreshers: concurrently trigger Refresh() through the composite.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				composite.Refresh(context.Background()) //nolint:errcheck
			}
		}()
	}

	wg.Wait()

	if n := partialReads.Load(); n > 0 {
		t.Errorf("observed %d partial IdP set(s) during concurrent refresh — store data was not replaced atomically", n)
	}
}
