//go:build unit

package metadata

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// buildAggregateXML returns an EntitiesDescriptor with n IdPs whose entity IDs
// are constructed from the given prefix (e.g. "https://set-a-%d.example.com").
func buildAggregateXML(prefix string, n int) []byte {
	xml := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	xml += `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="https://federation.example.org">` + "\n"
	for i := 0; i < n; i++ {
		entityID := fmt.Sprintf(prefix, i)
		ssoURL := fmt.Sprintf(prefix+"/sso", i)
		xml += fmt.Sprintf(`  <EntityDescriptor entityID=%q>`+"\n", entityID)
		xml += `    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + "\n"
		xml += fmt.Sprintf(`      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location=%q/>`+"\n", ssoURL)
		xml += `    </IDPSSODescriptor>` + "\n"
		xml += fmt.Sprintf(`    <Organization><OrganizationDisplayName xml:lang="en">IdP %d</OrganizationDisplayName></Organization>`+"\n", i)
		xml += `  </EntityDescriptor>` + "\n"
	}
	xml += `</EntitiesDescriptor>` + "\n"
	return []byte(xml)
}

// TestSimConcurrentReadsDuringRefresh verifies that concurrent readers always
// observe a consistent IdP list (exactly 10, never 0, never partial) while a
// Refresh() replaces the underlying data set.
func TestSimConcurrentReadsDuringRefresh(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ConcurrentReadsDuringRefresh")

	const numIdPs = 10
	const numReaders = 50
	const testDuration = 500 * time.Millisecond
	const refreshDelay = 100 * time.Millisecond

	setA := buildAggregateXML("https://set-a-idp%d.example.com", numIdPs)
	setB := buildAggregateXML("https://set-b-idp%d.example.com", numIdPs)

	// Atomic flag: 0 = serve set A, 1 = serve set B
	var serveSetB atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if serveSetB.Load() == 1 {
			w.Write(setB)
		} else {
			w.Write(setA)
		}
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("initial Load() failed: %v", err)
	}

	// Verify initial state
	initial, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() after load failed: %v", err)
	}
	if len(initial) != numIdPs {
		t.Fatalf("expected %d IdPs after initial load, got %d", numIdPs, len(initial))
	}

	var violations atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Launch reader goroutines
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}

				idps, err := store.ListIdPs("")
				if err != nil {
					violations.Add(1)
					continue
				}
				if len(idps) != numIdPs {
					violations.Add(1)
				}
			}
		}()
	}

	// After refreshDelay, switch to set B and trigger a Refresh
	time.AfterFunc(refreshDelay, func() {
		serveSetB.Store(1)
		// Expire the cache by using a zero TTL store trick: create a temporary
		// store pointing at the same server and call doRefresh force path.
		// Since we own the URLMetadataStore we call Refresh with an expired cache
		// by directly reaching its refresh path. We have to bypass the TTL — use
		// the force path by temporarily setting lastFetch to zero.
		store.mu.Lock()
		store.lastFetch = time.Time{} // zero it out to force re-fetch
		store.mu.Unlock()
		if err := store.Refresh(context.Background()); err != nil {
			// Non-fatal: record but don't stop the test
			t.Logf("Refresh() error (non-fatal): %v", err)
		}
	})

	time.Sleep(testDuration)
	close(stop)
	wg.Wait()

	if v := violations.Load(); v > 0 {
		t.Errorf("detected %d violation(s): readers observed an IdP count != %d", v, numIdPs)
	}

	// After refresh, readers should see the new set B
	final, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() after refresh failed: %v", err)
	}
	if len(final) != numIdPs {
		t.Errorf("expected %d IdPs after refresh, got %d", numIdPs, len(final))
	}
	if len(final) > 0 && final[0].EntityID[:10] != "https://se" {
		// Just verify we got set-b entities
		found := false
		for _, idp := range final {
			if len(idp.EntityID) > 14 && idp.EntityID[8:13] == "set-b" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected set-b IdPs after refresh, got: %v", final[0].EntityID)
		}
	}
}

// TestSimConcurrentRefreshCoalescing verifies that when multiple goroutines call
// Refresh() simultaneously, the second caller returns immediately (coalescing)
// rather than performing a redundant HTTP fetch.
func TestSimConcurrentRefreshCoalescing(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ConcurrentRefreshCoalescing")

	const numIdPs = 10
	xml := buildAggregateXML("https://coalesce-idp%d.example.com", numIdPs)

	// Track how many times the server actually receives requests
	var fetchCount atomic.Int64
	// Gate that holds the first request open until we release it
	gate := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		// Block the first request until the gate is released, simulating a slow server
		<-gate
		w.Header().Set("Content-Type", "application/xml")
		w.Write(xml)
	}))
	defer server.Close()

	// Create a store with a zero TTL to always trigger fetches
	store := NewURLMetadataStore(server.URL, 0)

	var wg sync.WaitGroup
	errs := make([]error, 2)

	// Launch two concurrent Refresh() calls
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.Refresh(context.Background())
	}()
	go func() {
		defer wg.Done()
		errs[1] = store.Refresh(context.Background())
	}()

	// Give both goroutines time to enter Refresh() and contend on the lock
	time.Sleep(20 * time.Millisecond)

	// Release the gate so the server can respond
	close(gate)
	wg.Wait()

	// Both calls must succeed (nil error)
	for i, err := range errs {
		if err != nil {
			t.Errorf("Refresh() call %d returned error: %v", i, err)
		}
	}

	// Only one HTTP request should have been made (the second coalesced)
	if n := fetchCount.Load(); n != 1 {
		t.Errorf("expected 1 HTTP fetch (coalescing), got %d", n)
	}
}

// TestSimETagNotModified verifies the 304 Not Modified path: after an initial
// load with an ETag, a subsequent Refresh() sends If-None-Match and when the
// server responds 304 the readers continue to see the unchanged data.
func TestSimETagNotModified(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ETagNotModified")

	const numIdPs = 10
	xml := buildAggregateXML("https://etag-idp%d.example.com", numIdPs)
	const testETag = `"stable-etag-v1"`

	var requestCount atomic.Int64
	var notModifiedCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.Header.Get("If-None-Match") == testETag {
			notModifiedCount.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("ETag", testETag)
		w.Write(xml)
	}))
	defer server.Close()

	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// Initial load: should receive full response with ETag
	if err := store.Load(); err != nil {
		t.Fatalf("initial Load() failed: %v", err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("expected 1 request after initial load, got %d", requestCount.Load())
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() after initial load failed: %v", err)
	}
	if len(idps) != numIdPs {
		t.Fatalf("expected %d IdPs after initial load, got %d", numIdPs, len(idps))
	}

	// Expire the cache
	fakeClock.Advance(11 * time.Second)

	// Second Refresh: should send If-None-Match → 304 → data unchanged
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() after 304 returned unexpected error: %v", err)
	}
	if requestCount.Load() != 2 {
		t.Errorf("expected 2 total requests, got %d", requestCount.Load())
	}
	if notModifiedCount.Load() != 1 {
		t.Errorf("expected 1 304 Not Modified response, got %d", notModifiedCount.Load())
	}

	// Readers must still see all IdPs unchanged after 304
	idps, err = store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() after 304 failed: %v", err)
	}
	if len(idps) != numIdPs {
		t.Errorf("expected %d IdPs after 304 (data unchanged), got %d", numIdPs, len(idps))
	}

	// Run concurrent readers briefly to confirm no data race around 304 path
	var violations atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				result, err := store.ListIdPs("")
				if err != nil || len(result) != numIdPs {
					violations.Add(1)
				}
			}
		}()
	}

	// Expire cache again and trigger another 304 while readers are running
	fakeClock.Advance(11 * time.Second)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh() after 304 failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if v := violations.Load(); v > 0 {
		t.Errorf("detected %d violation(s) during concurrent 304 path reads", v)
	}
}
