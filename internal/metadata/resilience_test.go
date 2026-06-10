//go:build unit

package metadata

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// expiredAggregateXML is a federation aggregate whose validUntil is in the past.
// ParseMetadata rejects it with ErrMetadataExpired, so a store loading it ends
// up with an empty IdP list (it never serves the expired entity descriptor).
const expiredAggregateXML = `<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2020-01-01T00:00:00Z">
  <EntityDescriptor entityID="https://stale-idp.example.com/saml">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://stale-idp.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

// freshAggregateXML is a valid aggregate with a far-future validUntil.
const freshAggregateXML = `<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2099-01-01T00:00:00Z">
  <EntityDescriptor entityID="https://fresh-idp.example.com/saml">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://fresh-idp.example.com/sso"/>
    </IDPSSODescriptor>
    <Organization><OrganizationDisplayName xml:lang="en">Fresh IdP</OrganizationDisplayName></Organization>
  </EntityDescriptor>
</EntitiesDescriptor>`

// TestCompositePartialDegradation verifies that when one source serves expired
// (rejected) metadata and another serves fresh metadata, a composite Load()
// returns an error but the fresh source's IdPs remain available.
func TestCompositePartialDegradation(t *testing.T) {
	staleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(expiredAggregateXML))
	}))
	defer staleServer.Close()

	freshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(freshAggregateXML))
	}))
	defer freshServer.Close()

	composite := NewCompositeMetadataStore([]ports.MetadataStore{
		NewURLMetadataStore(staleServer.URL, time.Hour),
		NewURLMetadataStore(freshServer.URL, time.Hour),
	})

	// Load reports the stale source's failure but does not abort.
	if err := composite.Load(); err == nil {
		t.Fatal("expected Load() to surface the expired-source error, got nil")
	}

	idps, err := composite.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(idps) != 1 {
		t.Fatalf("expected exactly the fresh source's 1 IdP after partial degradation, got %d", len(idps))
	}
	if idps[0].EntityID != "https://fresh-idp.example.com/saml" {
		t.Errorf("expected fresh IdP, got %q", idps[0].EntityID)
	}
}

// TestStartBackgroundRefreshIdempotent verifies that calling StartBackgroundRefresh
// twice does not start a second worker.
func TestStartBackgroundRefreshIdempotent(t *testing.T) {
	store := NewURLMetadataStore("https://example.com/metadata.xml", time.Hour)
	store.StartBackgroundRefresh(time.Hour)
	first := store.worker
	if first == nil {
		t.Fatal("expected a worker after first StartBackgroundRefresh")
	}
	store.StartBackgroundRefresh(time.Hour)
	if store.worker != first {
		t.Error("second StartBackgroundRefresh started a new worker; expected no-op")
	}
	_ = store.Close()
}

// TestURLStoreSelfHealsViaBackgroundRefresh verifies that a passively-constructed
// store whose initial load fails (expired metadata) recovers once
// StartBackgroundRefresh is called and the upstream begins serving fresh data.
func TestURLStoreSelfHealsViaBackgroundRefresh(t *testing.T) {
	var serveFresh atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if serveFresh.Load() {
			_, _ = w.Write([]byte(freshAggregateXML))
		} else {
			_, _ = w.Write([]byte(expiredAggregateXML))
		}
	}))
	defer server.Close()

	refreshed := make(chan error, 8)
	store := NewURLMetadataStore(server.URL, time.Millisecond,
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load fails: expired metadata is rejected, IdP list is empty.
	if err := store.Load(); err == nil {
		t.Fatal("expected initial Load() to fail on expired metadata")
	}
	if idps, _ := store.ListIdPs(""); len(idps) != 0 {
		t.Fatalf("expected empty IdP list after failed load, got %d", len(idps))
	}

	// Upstream recovers, then we promote the store to background refresh.
	serveFresh.Store(true)
	store.StartBackgroundRefresh(time.Millisecond)

	// Wait for a refresh tick that succeeds.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-refreshed:
			if err == nil {
				idps, _ := store.ListIdPs("")
				if len(idps) == 1 && idps[0].EntityID == "https://fresh-idp.example.com/saml" {
					return // healed
				}
			}
		case <-deadline:
			t.Fatal("store did not self-heal within deadline")
		}
	}
}

// TestCompositeCloseStopsChildWorkers verifies that closing the composite stops
// background workers started on its children.
func TestCompositeCloseStopsChildWorkers(t *testing.T) {
	child := NewURLMetadataStore("https://example.com/metadata.xml", time.Hour)
	composite := NewCompositeMetadataStore([]ports.MetadataStore{child})

	composite.StartBackgroundRefresh(time.Hour)
	if child.worker == nil {
		t.Fatal("expected child worker to be started via composite")
	}

	if err := composite.Close(); err != nil {
		t.Fatalf("composite Close() returned error: %v", err)
	}

	// A second Close on the child must be a safe no-op (worker already stopped),
	// confirming the composite forwarded Close to the child.
	if err := child.Close(); err != nil {
		t.Errorf("child Close() after composite Close() returned error: %v", err)
	}
}
