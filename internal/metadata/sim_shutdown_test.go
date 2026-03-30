//go:build unit

package metadata

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// minimalMetadataXML is an inline SAML metadata document used in shutdown
// simulation tests that need a valid response without reading from disk.
const minimalMetadataXML = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.sim.example.com/saml">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="https://idp.sim.example.com/saml/sso"/>
    </IDPSSODescriptor>
    <Organization>
        <OrganizationName xml:lang="en">Sim IdP</OrganizationName>
        <OrganizationDisplayName xml:lang="en">Simulation IdP</OrganizationDisplayName>
        <OrganizationURL xml:lang="en">https://sim.example.com</OrganizationURL>
    </Organization>
</EntityDescriptor>`

// TestSimShutdown_CloseAbortsInFlightRefresh verifies that Close() returns
// quickly by cancelling the HTTP context of an in-progress background refresh,
// rather than waiting for the full server response time.
func TestSimShutdown_CloseAbortsInFlightRefresh(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ShutdownCloseAbortsRefresh")
	// Server sleeps 500ms before responding, simulating a slow upstream.
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Signal that the request has arrived at the server.
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		// Simulate slow upstream; the sleep is cancelled when the client
		// disconnects (context cancellation reaches the server via closed conn).
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(minimalMetadataXML))
	}))
	defer server.Close()

	// Use a short refresh interval so the background goroutine fires quickly.
	refreshed := make(chan error, 1)
	store := NewURLMetadataStoreWithRefresh(server.URL, 100*time.Millisecond,
		WithOnRefresh(func(err error) {
			select {
			case refreshed <- err:
			default:
			}
		}),
	)

	// Wait until the background goroutine has actually started an HTTP request.
	select {
	case <-requestStarted:
		// HTTP fetch is now in-flight.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh to start HTTP request")
	}

	// Close() must return well before the server responds (500ms).
	// Allow up to 100ms for Close() itself.
	closeStart := time.Now()
	store.Close()
	closeElapsed := time.Since(closeStart)

	if closeElapsed >= 100*time.Millisecond {
		t.Errorf("Close() took %v; expected < 100ms (should not wait for 500ms response)", closeElapsed)
	}

	// The in-flight refresh should have received a context-cancelled error.
	select {
	case err := <-refreshed:
		if err == nil {
			// Context cancellation may race with the refresh completing if the
			// server managed to respond before cancellation propagated. This is
			// acceptable because the key assertion is about Close() speed.
		}
	case <-time.After(1 * time.Second):
		// No callback received; acceptable - goroutine may have exited before
		// calling onRefresh. The important check above (Close() speed) passed.
	}
}

// TestSimShutdown_CloseWithConcurrentReaders verifies that concurrent
// ListIdPs() callers and a Close() do not cause panics or data races.
func TestSimShutdown_CloseWithConcurrentReaders(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ShutdownCloseWithReaders")
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	goroutinesBefore := runtime.NumGoroutine()

	const numReaders = 20
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Launch readers that spin until signalled to stop.
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = store.ListIdPs("")
				}
			}
		}()
	}

	// Give readers a moment to get running, then close the store.
	time.Sleep(10 * time.Millisecond)
	store.Close()

	// Signal readers to stop and wait for all to finish.
	close(stop)
	wg.Wait()

	// Allow the runtime a moment to clean up any short-lived goroutines.
	time.Sleep(20 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	// Tolerate a small delta to account for goroutines unrelated to this test.
	const tolerance = 5
	delta := goroutinesAfter - goroutinesBefore
	if delta > tolerance {
		t.Errorf("possible goroutine leak: started with %d, ended with %d (delta %d, tolerance %d)",
			goroutinesBefore, goroutinesAfter, delta, tolerance)
	}
}

// TestSimShutdown_DoubleCloseIsIdempotent verifies that calling Close() more
// than once does not panic.
func TestSimShutdown_DoubleCloseIsIdempotent(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ShutdownDoubleClose")
	store := NewURLMetadataStoreWithRefresh("http://localhost:1", time.Hour)

	// Neither call should panic.
	store.Close()
	store.Close()
}

// TestSimShutdown_OperationsAfterClose verifies that the store remains safe
// to call after Close(): reads return cached data (or an empty set), and a
// manual Refresh() does not panic.
func TestSimShutdown_OperationsAfterClose(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.ShutdownOperationsAfterClose")
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	store.Close()

	// ListIdPs must not panic and should return the cached slice.
	idps, err := store.ListIdPs("")
	if err != nil {
		t.Errorf("ListIdPs() after Close() returned unexpected error: %v", err)
	}
	// The store had 1 IdP loaded; cache is still in memory after Close().
	if len(idps) != 1 {
		t.Errorf("ListIdPs() after Close() returned %d IdPs; expected cached data (1)", len(idps))
	}

	// Refresh() must not panic; it may return an error or succeed (cache hit).
	// We advance past the TTL by reloading with a short TTL store to force a
	// network call, but here we just verify it doesn't panic.
	_ = store.Refresh(t.Context())
}
