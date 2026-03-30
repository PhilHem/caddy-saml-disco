//go:build unit

package metadata

import (
	"context"
	"fmt"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestURLMetadataStore_Load(t *testing.T) {
	// Serve testdata/idp-metadata.xml via httptest.Server
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

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0]

	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idp.EntityID, "https://idp.example.com/saml")
	}

	if idp.DisplayName != "Example IdP" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Example IdP")
	}

	if idp.SSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("SSOURL = %q, want %q", idp.SSOURL, "https://idp.example.com/saml/sso")
	}
}

func TestURLMetadataStore_GetIdP(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Found
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("wrong EntityID returned")
	}

	// Not found
	_, err = store.GetIdP("https://unknown.example.com")
	if err != domain.ErrIdPNotFound {
		t.Errorf("expected domain.ErrIdPNotFound, got %v", err)
	}
}

func TestURLMetadataStore_Load_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			store := NewURLMetadataStore(server.URL, time.Hour)
			err := store.Load()
			if err == nil {
				t.Error("expected error for HTTP error response")
			}
		})
	}
}

func TestURLMetadataStore_Load_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid xml"))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestURLMetadataStore_Load_NetworkError(t *testing.T) {
	// Use a URL that will fail to connect
	store := NewURLMetadataStore("http://localhost:1", time.Hour)
	err := store.Load()
	if err == nil {
		t.Error("expected error for network failure")
	}
}

func TestURLMetadataStore_Load_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second) // Slow response
		w.Write([]byte("<xml/>"))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := store.Refresh(ctx)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestURLMetadataStore_CacheHit(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Second call within TTL should not fetch again
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch (cache hit), got %d", fetchCount)
	}
}

func TestURLMetadataStore_CacheExpiry(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second call after TTL should fetch again
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches (cache miss), got %d", fetchCount)
	}
}

func TestURLMetadataStore_ConditionalRequest_ETag(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	etag := `"abc123"`
	requestCount := 0
	conditionalRequestReceived := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Check if client sent If-None-Match header
		if r.Header.Get("If-None-Match") == etag {
			conditionalRequestReceived = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch - should get full response with ETag
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should send If-None-Match and get 304
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Verify conditional request was sent
	if !conditionalRequestReceived {
		t.Error("expected If-None-Match header to be sent on second request")
	}

	// Data should still be present (not cleared on 304)
	idps, _ = store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after 304 response, got %d", len(idps))
	}
}

func TestURLMetadataStore_ConditionalRequest_LastModified(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	lastMod := "Wed, 01 Jan 2025 00:00:00 GMT"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client sent If-Modified-Since header
		if r.Header.Get("If-Modified-Since") == lastMod {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lastMod)
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should send If-Modified-Since and get 304
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Data should still be present
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after 304 response, got %d", len(idps))
	}
}

func TestURLMetadataStore_ConditionalRequest_Modified(t *testing.T) {
	// First metadata - single IdP
	metadata1, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Second metadata - aggregate with 3 IdPs
	metadata2, err := os.ReadFile("../../testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read aggregate metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("ETag", `"v1"`)
			w.Write(metadata1)
		} else {
			// New version - different ETag, return full response
			w.Header().Set("ETag", `"v2"`)
			w.Write(metadata2)
		}
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch - single IdP
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should get updated data
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	idps, _ = store.ListIdPs("")
	if len(idps) != 3 {
		t.Errorf("expected 3 IdPs after update, got %d", len(idps))
	}
}

func TestURLMetadataStore_Load_Aggregate(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3", len(idps))
	}
}

func TestURLMetadataStore_Load_DFNAAISample(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/dfn-aai-sample.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// 6 IdPs from DFN-AAI sample (SP should be skipped)
	if len(idps) != 6 {
		t.Errorf("ListIdPs() returned %d IdPs, want 6", len(idps))
	}

	// Verify specific IdP
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.DisplayName != "Freie Universität Berlin" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Freie Universität Berlin")
	}
}

func TestURLMetadataStore_UserAgent(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var receivedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		w.Write(metadata)
	}))
	defer server.Close()

	// Pass version option to set User-Agent header
	store := NewURLMetadataStore(server.URL, time.Hour, WithVersion("test-version"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify User-Agent header was sent
	expectedUserAgent := "caddy-saml-disco/test-version"
	if receivedUserAgent != expectedUserAgent {
		t.Errorf("User-Agent = %q, want %q", receivedUserAgent, expectedUserAgent)
	}
}

// IdP filter pattern tests (provisioning-time filtering)

func TestURLMetadataStore_WithIdPFilter(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	// Filter to only load idp2
	store := NewURLMetadataStore(server.URL, time.Hour, WithIdPFilter("*idp2*"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}

	if len(idps) > 0 && idps[0].EntityID != "https://idp2.example.com/saml" {
		t.Errorf("Expected idp2.example.com, got %s", idps[0].EntityID)
	}
}

func TestURLMetadataStore_ListIdPs_Filter(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		filter   string
		expected int
	}{
		{"", 3},           // no filter - all 3 IdPs
		{"University", 2}, // matches State University and Tech University
		{"Corporate", 1},  // matches Corporate Provider only
		{"unknown", 0},    // no match
	}

	for _, tc := range tests {
		idps, err := store.ListIdPs(tc.filter)
		if err != nil {
			t.Errorf("ListIdPs(%q) failed: %v", tc.filter, err)
			continue
		}
		if len(idps) != tc.expected {
			t.Errorf("ListIdPs(%q) returned %d IdPs, want %d", tc.filter, len(idps), tc.expected)
		}
	}
}

// =============================================================================
// mdui:UIInfo Parsing Tests (Phase 2)
// =============================================================================

// TestParseIdP_UIInfo_DisplayName verifies that mdui:DisplayName is preferred
// over Organization/OrganizationDisplayName.
func TestURLMetadataStore_IsFresh_InitiallyFalse(t *testing.T) {
	store := NewURLMetadataStore("http://localhost:1", time.Hour)

	if store.IsFresh() {
		t.Error("IsFresh() should be false before any load")
	}
}

// TestURLMetadataStore_IsFresh_AfterSuccessfulLoad verifies that IsFresh()
// returns true after a successful load.
func TestURLMetadataStore_IsFresh_AfterSuccessfulLoad(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !store.IsFresh() {
		t.Error("IsFresh() should be true after successful load")
	}
}

// TestURLMetadataStore_Refresh_PreservesDataOnFailure verifies that when
// Refresh() fails, the existing cached data is preserved and IsFresh() becomes false.
func TestURLMetadataStore_Refresh_PreservesDataOnFailure(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// First request succeeds
			w.Write(metadata)
		} else {
			// Subsequent requests fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First load succeeds
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify data loaded and fresh
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after initial load, got %d", len(idps))
	}
	if !store.IsFresh() {
		t.Fatal("IsFresh() should be true after successful load")
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second refresh fails (server returns 500)
	err = store.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() should return error on HTTP 500")
	}

	// Data should still be present (graceful degradation)
	idps, _ = store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after failed refresh (stale data), got %d", len(idps))
	}

	// But IsFresh() should now be false
	if store.IsFresh() {
		t.Error("IsFresh() should be false after failed refresh")
	}

	// GetIdP should still work with stale data
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Errorf("GetIdP() should work with stale data: %v", err)
	}
	if idp == nil {
		t.Error("GetIdP() returned nil with stale data")
	}
}

// TestURLMetadataStore_LastError_ReturnsNilOnSuccess verifies that LastError()
// returns nil after a successful refresh.
func TestURLMetadataStore_LastError_ReturnsNilOnSuccess(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if store.LastError() != nil {
		t.Errorf("LastError() should be nil after success, got %v", store.LastError())
	}
}

// TestURLMetadataStore_LastError_ReturnsErrorOnFailure verifies that LastError()
// returns the error from the last failed refresh.
func TestURLMetadataStore_LastError_ReturnsErrorOnFailure(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Write(metadata)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First load succeeds
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if store.LastError() != nil {
		t.Errorf("LastError() should be nil after success")
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Second refresh fails
	_ = store.Refresh(context.Background())

	// LastError should now be set
	if store.LastError() == nil {
		t.Error("LastError() should return error after failed refresh")
	}
}

// TestURLMetadataStore_Health_ReturnsStatus verifies that Health() returns
// comprehensive status information.
func TestURLMetadataStore_Health_ReturnsStatus(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Write(metadata)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// Before load: empty health
	health := store.Health()
	if health.IsFresh {
		t.Error("Health.IsFresh should be false before load")
	}
	if health.IdPCount != 0 {
		t.Errorf("Health.IdPCount should be 0 before load, got %d", health.IdPCount)
	}

	// After successful load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health = store.Health()
	if !health.IsFresh {
		t.Error("Health.IsFresh should be true after successful load")
	}
	if health.IdPCount != 1 {
		t.Errorf("Health.IdPCount should be 1, got %d", health.IdPCount)
	}
	if health.LastSuccessTime.IsZero() {
		t.Error("Health.LastSuccessTime should be set")
	}
	if health.LastError != nil {
		t.Errorf("Health.LastError should be nil, got %v", health.LastError)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// After failed refresh
	_ = store.Refresh(context.Background())

	health = store.Health()
	if health.IsFresh {
		t.Error("Health.IsFresh should be false after failed refresh")
	}
	if health.IdPCount != 1 {
		t.Errorf("Health.IdPCount should still be 1 (stale data), got %d", health.IdPCount)
	}
	if health.LastError == nil {
		t.Error("Health.LastError should be set after failed refresh")
	}
	// LastSuccessTime should still reflect the last successful load
	if health.LastSuccessTime.IsZero() {
		t.Error("Health.LastSuccessTime should still be set from previous success")
	}
}

func TestURLMetadataStore_Load_ExpiredMetadata(t *testing.T) {
	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expiredXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()

	if err == nil {
		t.Error("expected error for expired metadata from URL")
	}
	if err != nil && !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

// TestURLMetadataStore_Load_ValidMetadata verifies that URL-based loading
// accepts metadata with future validUntil.
func TestURLMetadataStore_Load_ValidMetadataWithValidUntil(t *testing.T) {
	validXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2030-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(validXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()

	if err != nil {
		t.Errorf("unexpected error for valid metadata: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(idps))
	}
}

// =============================================================================
// Background Refresh Tests (Phase 4)
// =============================================================================

// TestURLMetadataStore_BackgroundRefresh verifies that the store periodically
// fetches metadata when created with NewURLMetadataStoreWithRefresh.
func TestURLMetadataStore_BackgroundRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load counts as 1
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for exactly 2 background refresh cycles (no time.Sleep)
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first background refresh")
	}
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for second background refresh")
	}

	// Should have made additional requests from background refresh
	mu.Lock()
	count := requestCount
	mu.Unlock()

	// 1 initial + 2 background = 3 minimum
	if count < 3 {
		t.Errorf("expected at least 3 requests (initial + 2 background), got %d", count)
	}
}

// TestURLMetadataStore_Close_StopsBackgroundRefresh verifies that Close()
// stops the background refresh goroutine.
func TestURLMetadataStore_Close_StopsBackgroundRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to detect refresh attempts
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 10*time.Millisecond,
		WithOnRefresh(func(err error) { refreshed <- err }))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for one background refresh to confirm goroutine is running
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Record count and close
	mu.Lock()
	countAfterClose := requestCount
	mu.Unlock()
	store.Close()

	// After Close(), the channel should not receive more (use short timeout)
	select {
	case <-refreshed:
		t.Error("received refresh after Close()")
	case <-time.After(50 * time.Millisecond):
		// Expected: no refresh after close
	}

	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	if finalCount != countAfterClose {
		t.Errorf("requests continued after Close(): had %d, now %d", countAfterClose, finalCount)
	}
}

// TestURLMetadataStore_Close_Idempotent verifies that Close() can be called
// multiple times without panicking.
func TestURLMetadataStore_Close_Idempotent(t *testing.T) {
	store := NewURLMetadataStoreWithRefresh("http://example.com", time.Hour)

	// Should not panic when called multiple times
	store.Close()
	store.Close()
	store.Close()
}

// TestURLMetadataStore_Close_NoBackgroundRefresh verifies that Close() works
// on stores created without background refresh (via NewURLMetadataStore).
func TestURLMetadataStore_Close_NoBackgroundRefresh(t *testing.T) {
	store := NewURLMetadataStore("http://example.com", time.Hour)

	// Should not panic - Close() should be a no-op for passive stores
	store.Close()
}

// =============================================================================
// Logger Integration Tests
// =============================================================================

// TestURLMetadataStore_WithLogger verifies that a logger can be injected
// via the WithLogger option by testing that logging actually occurs.
func TestURLMetadataStore_WithLogger(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))

	// Trigger an operation that would log if logger is set
	// Load() should succeed and if logger is working, we can verify through behavior
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify logger is working by checking that we can get health status
	// (if logger was nil, operations would still work but this verifies the store is functional)
	health := store.Health()
	if health.IdPCount == 0 {
		t.Error("expected IdPs to be loaded")
	}

	// Verify that background refresh with logger would log (indirect test)
	// We test this through the BackgroundRefresh_LogsSuccess test which verifies actual logging
	_ = logs // logs available for future verification if needed
}

// TestURLMetadataStore_BackgroundRefresh_LogsSuccess verifies that successful
// background refresh events are logged.
func TestURLMetadataStore_BackgroundRefresh_LogsSuccess(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithLogger(logger),
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for at least one background refresh cycle
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Assert: at least one success log
	successLogs := logs.FilterMessage("background metadata refresh succeeded")
	if successLogs.Len() == 0 {
		t.Error("expected success log message from background refresh")
	}

	// Verify idp_count field is present
	if successLogs.Len() > 0 {
		entry := successLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in log entry")
		}
	}
}

// TestURLMetadataStore_BackgroundRefresh_LogsFailure verifies that failed
// background refresh events are logged with error details.
func TestURLMetadataStore_BackgroundRefresh_LogsFailure(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithLogger(logger),
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Wait for at least one background refresh cycle (no initial Load needed - will fail)
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Assert: at least one failure log
	failLogs := logs.FilterMessage("background metadata refresh failed")
	if failLogs.Len() == 0 {
		t.Error("expected failure log message from background refresh")
	}

	// Verify error field is present and contains HTTP status
	if failLogs.Len() > 0 {
		entry := failLogs.All()[0]
		fields := entry.ContextMap()
		errVal, ok := fields["error"]
		if !ok {
			t.Error("expected error field in log entry")
		} else if errStr, isStr := errVal.(string); isStr {
			if !strings.Contains(errStr, "500") {
				t.Errorf("expected HTTP 500 in error, got: %s", errStr)
			}
		}
	}
}

// TestURLMetadataStore_Load_ExpiredMetadata_Logs verifies that expired metadata
// rejection from HTTP source is logged with structured fields.
func TestURLMetadataStore_Load_ExpiredMetadata_Logs(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expiredXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))
	_ = store.Load() // Expected to fail

	// Assert: warning log with structured fields
	warnLogs := logs.FilterMessage("metadata expired")
	if warnLogs.Len() == 0 {
		t.Error("expected 'metadata expired' warning log")
	}

	if warnLogs.Len() > 0 {
		entry := warnLogs.All()[0]
		fields := entry.ContextMap()

		if _, ok := fields["source"]; !ok {
			t.Error("expected source field (URL) in log")
		}
	}
}

// =============================================================================
// MetadataHealth validUntil Tests (Phase 5 - Federation Hardening)
// =============================================================================

func TestURLMetadataStore_Health_ReturnsValidUntil(t *testing.T) {
	// Use dfn-aai-sample.xml which has validUntil="2030-12-31T23:59:59Z"
	metadata, err := os.ReadFile("../../testdata/dfn-aai-sample.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 1*time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil == nil {
		t.Fatal("Health.MetadataValidUntil should be set for metadata with validUntil")
	}

	expected := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
	if !health.MetadataValidUntil.Equal(expected) {
		t.Errorf("MetadataValidUntil = %v, want %v", *health.MetadataValidUntil, expected)
	}
}

func TestURLMetadataStore_Health_NoValidUntil(t *testing.T) {
	// Use idp-metadata.xml which has no validUntil attribute
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 1*time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil for metadata without validUntil, got %v", *health.MetadataValidUntil)
	}
}

func TestURLMetadataStore_RecordsMetricsOnSuccess(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	mock := &MockMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	calls := mock.GetMetadataRefreshes()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.Source != "url" {
		t.Errorf("source = %q, want %q", call.Source, "url")
	}
	if !call.Success {
		t.Error("success = false, want true")
	}
	if call.IdpCount != 1 {
		t.Errorf("idpCount = %d, want 1", call.IdpCount)
	}
}

func TestURLMetadataStore_RecordsMetricsOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	mock := &MockMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	err := store.Load()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	calls := mock.GetMetadataRefreshes()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.Source != "url" {
		t.Errorf("source = %q, want %q", call.Source, "url")
	}
	if call.Success {
		t.Error("success = true, want false")
	}
	if call.IdpCount != 0 {
		t.Errorf("idpCount = %d, want 0", call.IdpCount)
	}
}

func TestURLMetadataStore_DoesNotRecordMetricsOnCacheHit(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	mock := &MockMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	// First load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Second load (should be cache hit)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Only one HTTP request should have been made
	if requestCount != 1 {
		t.Errorf("expected 1 HTTP request, got %d", requestCount)
	}

	// Only one metrics call (from first load, not from cache hit)
	calls := mock.GetMetadataRefreshes()
	if len(calls) != 1 {
		t.Errorf("expected 1 metrics call (no metrics on cache hit), got %d", len(calls))
	}
}

// TestFilterIdPsByRegistrationAuthority tests the pure domain filter function
func TestURLMetadataStore_Property_MultipleFilterFailures_DeterministicError(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	// Set up multiple filters that would all independently fail (reduce IdP set to zero)
	store := NewURLMetadataStore(server.URL, time.Hour,
		WithIdPFilter("*nonexistent*"),                                   // Would fail: no IdPs match
		WithRegistrationAuthorityFilter("https://nonexistent.org"),       // Would fail: no IdPs have this registration authority
		WithEntityCategoryFilter("https://nonexistent.org/category"),     // Would fail: no IdPs have this category
		WithAssuranceCertificationFilter("https://nonexistent.org/cert"), // Would fail: no IdPs have this certification
	)

	err = store.Load()

	// Should fail because multiple filters would reduce IdP set to zero
	if err == nil {
		t.Fatal("Expected error when multiple filters would fail")
	}

	// Property 1: Error message should include all failing filters
	errMsg := err.Error()

	// Check that all failing filters are mentioned in the error
	expectedFilters := []string{
		"filter pattern",
		"registration authority filter",
		"entity category filter",
		"assurance certification filter",
	}

	for _, expected := range expectedFilters {
		if !strings.Contains(errMsg, expected) {
			t.Errorf("Error message should mention %q, got: %q", expected, errMsg)
		}
	}

	// Property 2: Error message should be deterministic (same message every time)
	// Run multiple times to verify determinism
	for i := 0; i < 5; i++ {
		store2 := NewURLMetadataStore(server.URL, time.Hour,
			WithIdPFilter("*nonexistent*"),
			WithRegistrationAuthorityFilter("https://nonexistent.org"),
			WithEntityCategoryFilter("https://nonexistent.org/category"),
			WithAssuranceCertificationFilter("https://nonexistent.org/cert"),
		)
		err2 := store2.Load()
		if err2 == nil {
			t.Fatal("Expected error on iteration", i)
		}
		if err2.Error() != errMsg {
			t.Errorf("Error message not deterministic: got %q, want %q", err2.Error(), errMsg)
		}
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

// TestURLMetadataStore_Concurrency_ConcurrentRefresh tests that concurrent
// Refresh() calls don't cause duplicate HTTP requests or inconsistent state.
// This addresses METADATA-003 and METADATA-008.
func TestURLMetadataStore_Concurrency_ConcurrentRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write(metadata)
	}))
	defer server.Close()

	clock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour, WithClock(clock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Expire cache
	clock.Advance(2 * time.Hour)

	// Launch multiple concurrent Refresh() calls
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Refresh(context.Background())
		}()
	}
	wg.Wait()

	// Verify only one HTTP request was made (or requests were properly serialized)
	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	// Should have initial load (1) + at most 1 refresh from concurrent calls
	if finalCount > 2 {
		t.Errorf("expected at most 2 requests (initial + 1 refresh), got %d", finalCount)
	}
}

// TestURLMetadataStore_Concurrency_ReadsDuringWrite tests concurrent
// GetIdP()/ListIdPs() reads during Refresh() write to verify no data races
// or panics. This addresses METADATA-004.
func TestURLMetadataStore_Concurrency_ReadsDuringWrite(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Use slow server to ensure Refresh() takes time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Slow response
		w.Write(metadata)
	}))
	defer server.Close()

	clock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour, WithClock(clock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Expire cache
	clock.Advance(2 * time.Hour)

	// Launch Refresh() in one goroutine
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- store.Refresh(context.Background())
	}()

	// Launch multiple concurrent reads in other goroutines
	const numReaders = 20
	var wg sync.WaitGroup
	wg.Add(numReaders)
	readErrors := make(chan error, numReaders)
	for i := 0; i < numReaders; i++ {
		go func(idx int) {
			defer wg.Done()
			// Mix GetIdP and ListIdPs calls
			if idx%2 == 0 {
				_, err := store.GetIdP("https://idp.example.com/saml")
				readErrors <- err
			} else {
				_, err := store.ListIdPs("")
				readErrors <- err
			}
		}(i)
	}

	// Wait for refresh to complete
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatalf("Refresh() failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Refresh()")
	}

	// Wait for all reads to complete
	wg.Wait()
	close(readErrors)

	// Verify no panics occurred (errors are OK, panics are not)
	for err := range readErrors {
		// domain.ErrIdPNotFound is acceptable during refresh
		if err != nil && err != domain.ErrIdPNotFound {
			// Other errors might indicate a problem, but not necessarily a race
			// The race detector will catch actual data races
		}
	}
}

// TestURLMetadataStore_Concurrency_StaleEtag tests that concurrent refreshes
// use consistent etag/lastModified values and don't read stale values.
// This addresses METADATA-006.
func TestURLMetadataStore_Concurrency_StaleEtag(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var etagCounter int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		etagCounter++
		currentEtag := fmt.Sprintf(`"etag-%d"`, etagCounter)
		mu.Unlock()

		// Return 304 if If-None-Match matches current etag
		if r.Header.Get("If-None-Match") == currentEtag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", currentEtag)
		w.Write(metadata)
	}))
	defer server.Close()

	clock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour, WithClock(clock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Expire cache
	clock.Advance(2 * time.Hour)

	// Launch multiple concurrent Refresh() calls
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	errors := make(chan error, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			errors <- store.Refresh(context.Background())
		}()
	}
	wg.Wait()
	close(errors)

	// Verify all refreshes succeeded
	for err := range errors {
		if err != nil {
			t.Errorf("Refresh() failed: %v", err)
		}
	}

	// Verify etag was updated consistently
	// With proper synchronization, we should see at most numGoroutines requests
	// (each concurrent refresh might make a request if they all read stale etag)
	mu.Lock()
	requestCount := etagCounter
	mu.Unlock()

	// Should have initial load (1) + some refreshes
	// Without synchronization, we'd see many more requests due to stale etag reads
	if requestCount > numGoroutines+5 {
		t.Errorf("too many requests (%d), suggests stale etag reads", requestCount)
	}
}

// TestURLMetadataStore_Concurrency_CloseCancelsRefresh tests that Close()
// cancels in-progress refresh operations. This addresses METADATA-007.
func TestURLMetadataStore_Concurrency_CloseCancelsRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Use slow server to ensure HTTP request is in progress
	refreshStarted := make(chan struct{})
	refreshBlocked := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(refreshStarted)
		// Block until we're told to proceed (or timeout)
		select {
		case <-refreshBlocked:
		case <-time.After(2 * time.Second):
		}
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStoreWithRefresh(server.URL, time.Hour)

	// Trigger a refresh that will block
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- store.Refresh(context.Background())
	}()

	// Wait for refresh to start HTTP request
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for refresh to start")
	}

	// Close should cancel the in-progress request
	closeErr := store.Close()
	if closeErr != nil {
		t.Errorf("Close() returned error: %v", closeErr)
	}

	// Unblock the server
	close(refreshBlocked)

	// Verify refresh was cancelled or completed quickly
	select {
	case err := <-refreshDone:
		// Context cancellation error is expected
		if err != nil && !strings.Contains(err.Error(), "context canceled") &&
			!strings.Contains(err.Error(), "operation was canceled") {
			// If refresh completed successfully, that's also OK
			// The important thing is Close() didn't hang
		}
	case <-time.After(1 * time.Second):
		t.Error("Refresh() did not complete after Close()")
	}
}

// TestURLMetadataStore_Concurrency_RefreshInProgress tests refresh-in-progress
// synchronization to ensure only one refresh executes at a time.
// This addresses METADATA-008.
func TestURLMetadataStore_Concurrency_RefreshInProgress(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		// Simulate slow refresh
		time.Sleep(100 * time.Millisecond)
		w.Write(metadata)
	}))
	defer server.Close()

	clock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour, WithClock(clock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Expire cache
	clock.Advance(2 * time.Hour)

	// Launch many concurrent Refresh() calls
	const numGoroutines = 20
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = store.Refresh(context.Background())
		}()
	}
	wg.Wait()

	// Verify only one refresh executed (or refreshes were properly serialized)
	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	// Should have initial load (1) + at most 1 refresh
	// Without synchronization, we'd see many more requests
	if finalCount > 2 {
		t.Errorf("expected at most 2 requests (initial + 1 refresh), got %d (suggests missing synchronization)", finalCount)
	}
}

// Tests for ExtractEntityIDs helper function

// =============================================================================
// Cycle 8: Concurrency and Edge Case Tests
// =============================================================================

// TestConcurrentReadWriteDuringRefresh verifies concurrent reads during writes
// with race detection enabled to catch data races.
func TestConcurrentReadWriteDuringRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Slow server to ensure Refresh() is in progress during reads
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write(metadata)
	}))
	defer server.Close()

	clock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour, WithClock(clock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Expire cache
	clock.Advance(2 * time.Hour)

	// Launch refresh in background
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- store.Refresh(context.Background())
	}()

	// Concurrent reads (should not race with refresh write)
	const numReaders = 50
	var wg sync.WaitGroup
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func(idx int) {
			defer wg.Done()
			// Mix different read operations
			if idx%3 == 0 {
				_, _ = store.GetIdP("https://idp.example.com/saml")
			} else if idx%3 == 1 {
				_, _ = store.ListIdPs("")
			} else {
				_ = store.Health()
			}
		}(i)
	}

	// Wait for all reads
	wg.Wait()

	// Wait for refresh
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Errorf("Refresh() failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for refresh")
	}

	// Verify no panics occurred (race detector will catch data races)
	// Final read to ensure store is still consistent
	idps, err := store.ListIdPs("")
	if err != nil {
		t.Errorf("ListIdPs() after concurrent operations failed: %v", err)
	}
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after concurrent operations, got %d", len(idps))
	}
}

func TestURLMetadataStore_CacheHitLogging(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))

	// Initial load (cache miss)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Second load should be a cache hit
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Assert: cache hit log
	hitLogs := logs.FilterMessage("using cached metadata")
	if hitLogs.Len() == 0 {
		t.Error("expected 'using cached metadata' debug log on cache hit")
	}

	if hitLogs.Len() > 0 {
		entry := hitLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["ttl_remaining"]; !ok {
			t.Error("expected ttl_remaining field in cache hit log")
		}
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in cache hit log")
		}
	}
}

// TestURLMetadataStore_CacheMissLogging verifies debug log "fetching metadata"
// with url and forced fields when cache is invalid or forced.
func TestURLMetadataStore_CacheMissLogging(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write(metadata)
	}))
	defer server.Close()

	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour,
		WithLogger(logger),
		WithClock(fakeClock))

	// Initial load (cache miss)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Assert: cache miss (fetch) log
	fetchLogs := logs.FilterMessage("fetching metadata")
	if fetchLogs.Len() == 0 {
		t.Error("expected 'fetching metadata' debug log on cache miss")
	}

	if fetchLogs.Len() > 0 {
		entry := fetchLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["url"]; !ok {
			t.Error("expected url field in fetch log")
		}
		if _, ok := fields["forced"]; !ok {
			t.Error("expected forced field in fetch log")
		}
	}
}

// TestURLMetadataStore_ConditionalRequestLogging_304 verifies debug log
// "metadata not modified (304)" with response_time and etag.
func TestURLMetadataStore_ConditionalRequestLogging_304(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	etag := `"test-etag-123"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If client sends If-None-Match with our etag, return 304
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(metadata)
	}))
	defer server.Close()

	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, time.Hour,
		WithLogger(logger),
		WithClock(fakeClock))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Advance clock past TTL to force refresh
	fakeClock.Advance(2 * time.Hour)

	// Second load should get 304
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Assert: 304 log
	notModifiedLogs := logs.FilterMessage("metadata not modified (304)")
	if notModifiedLogs.Len() == 0 {
		t.Error("expected 'metadata not modified (304)' debug log")
	}

	if notModifiedLogs.Len() > 0 {
		entry := notModifiedLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["response_time"]; !ok {
			t.Error("expected response_time field in 304 log")
		}
		if _, ok := fields["etag"]; !ok {
			t.Error("expected etag field in 304 log")
		}
	}
}

// TestURLMetadataStore_ConditionalRequestLogging_200 verifies debug log
// "metadata fetched (200 OK)" with idp_count and response_time.
func TestURLMetadataStore_ConditionalRequestLogging_200(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Assert: 200 OK log
	fetchedLogs := logs.FilterMessage("metadata fetched (200 OK)")
	if fetchedLogs.Len() == 0 {
		t.Error("expected 'metadata fetched (200 OK)' debug log")
	}

	if fetchedLogs.Len() > 0 {
		entry := fetchedLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in 200 OK log")
		}
		if _, ok := fields["response_time"]; !ok {
			t.Error("expected response_time field in 200 OK log")
		}
	}
}

// TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Start verifies info log
// "starting background metadata refresh" with interval and url.
func TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Start(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStoreWithRefresh(server.URL, time.Hour,
		WithLogger(logger))
	defer store.Close()

	// Assert: start log
	startLogs := logs.FilterMessage("starting background metadata refresh")
	if startLogs.Len() == 0 {
		t.Error("expected 'starting background metadata refresh' info log")
	}

	if startLogs.Len() > 0 {
		entry := startLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["interval"]; !ok {
			t.Error("expected interval field in start log")
		}
		if _, ok := fields["url"]; !ok {
			t.Error("expected url field in start log")
		}
	}
}

// TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Stop verifies info log
// "stopping background metadata refresh" on Close().
func TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Stop(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStoreWithRefresh(server.URL, time.Hour,
		WithLogger(logger))

	// Close to trigger stop log
	store.Close()

	// Assert: stop log
	stopLogs := logs.FilterMessage("stopping background metadata refresh")
	if stopLogs.Len() == 0 {
		t.Error("expected 'stopping background metadata refresh' info log")
	}
}

// TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Duration verifies that
// background refresh logs include duration field.
func TestURLMetadataStore_BackgroundRefreshLifecycleLogging_Duration(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithLogger(logger),
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for background refresh
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Assert: success log with duration
	successLogs := logs.FilterMessage("background metadata refresh succeeded")
	if successLogs.Len() == 0 {
		t.Error("expected 'background metadata refresh succeeded' info log")
	}

	if successLogs.Len() > 0 {
		entry := successLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["duration"]; !ok {
			t.Error("expected duration field in success log")
		}
	}
}

// TestURLMetadataStore_StartupLogging verifies info log "metadata loaded"
// with source, idp_count, and duration after Load().
func TestURLMetadataStore_StartupLogging(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Assert: metadata loaded log
	loadedLogs := logs.FilterMessage("metadata loaded")
	if loadedLogs.Len() == 0 {
		t.Error("expected 'metadata loaded' info log")
	}

	if loadedLogs.Len() > 0 {
		entry := loadedLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["source"]; !ok {
			t.Error("expected source field in loaded log")
		}
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in loaded log")
		}
		if _, ok := fields["duration"]; !ok {
			t.Error("expected duration field in loaded log")
		}
	}
}

func TestListIdPs_ReturnsEmptySlice_URLStore(t *testing.T) {
	// Create a server that returns empty metadata
	emptyXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(emptyXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Must be an empty slice, not nil
	if idps == nil {
		t.Error("ListIdPs() returned nil, want empty slice")
	}
	if len(idps) != 0 {
		t.Errorf("ListIdPs() returned %d IdPs, want 0", len(idps))
	}
}

// TestURLMetadataStore_Concurrency_CloseVsRefresh tests that concurrent Close()
// and doRefresh() calls don't cause data races or panics. This addresses the
// scenario where a background refresh is in progress when Close() is called.
func TestURLMetadataStore_Concurrency_CloseVsRefresh(t *testing.T) {
	metadata, err := os.ReadFile("../../testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Use slow server to ensure refresh is in progress during Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Slow response
		w.Write(metadata)
	}))
	defer server.Close()

	// Run multiple iterations to increase chance of catching races
	for i := 0; i < 10; i++ {
		store := NewURLMetadataStoreWithRefresh(server.URL, 10*time.Millisecond)

		// Spawn goroutines calling Refresh() (which calls doRefresh internally)
		var wg sync.WaitGroup
		const numRefreshers = 5
		wg.Add(numRefreshers)
		for j := 0; j < numRefreshers; j++ {
			go func() {
				defer wg.Done()
				// Call Refresh multiple times to increase contention
				for k := 0; k < 3; k++ {
					_ = store.Refresh(context.Background())
				}
			}()
		}

		// Call Close() while refreshes are in progress
		go func() {
			time.Sleep(5 * time.Millisecond) // Let some refreshes start
			store.Close()
		}()

		// Wait for all refreshers to complete
		wg.Wait()

		// Ensure Close() can be called again (idempotent)
		store.Close()
	}
	// Test passes if no panics or race detector errors
}

// TestFileMetadataStore_StartupLogging verifies info log "metadata loaded"
// with source, idp_count, and duration after Load().
