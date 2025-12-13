//go:build integration

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
)

// TestLogoProxy_FullFlow tests the complete logo proxy flow:
// 1. Set up a test logo server
// 2. Create metadata with IdP pointing to test logo
// 3. Request logo through proxy endpoint
// 4. Verify logo is served correctly and cached
func TestLogoProxy_FullFlow(t *testing.T) {
	logoData := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A} // PNG magic bytes

	fetchCount := 0
	logoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "image/png")
		w.Write(logoData)
	}))
	defer logoServer.Close()

	// Create metadata store with IdP that has logo URL
	metadataStore := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{{
		EntityID:    "https://idp.example.com",
		DisplayName: "Example IdP",
		LogoURL:     logoServer.URL + "/logo.png",
	}})

	// Create caching logo store
	logoStore := caddysamldisco.NewCachingLogoStore(metadataStore, nil)

	// Create plugin
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(metadataStore)
	disco.SetLogoStore(logoStore)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// First request - should fetch from origin
	entityID := url.PathEscape("https://idp.example.com")
	resp, err := http.Get(server.URL + "/saml/api/logo/" + entityID)
	if err != nil {
		t.Fatalf("GET logo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.Header.Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Error("Cache-Control header not set")
	}

	body := make([]byte, len(logoData)+10)
	n, _ := resp.Body.Read(body)
	if !bytes.Equal(body[:n], logoData) {
		t.Errorf("body = %v, want %v", body[:n], logoData)
	}

	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1", fetchCount)
	}

	// Second request - should use cache
	resp2, err := http.Get(server.URL + "/saml/api/logo/" + entityID)
	if err != nil {
		t.Fatalf("GET logo (cached): %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("cached status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount after cache = %d, want 1", fetchCount)
	}
}

// TestLogoProxy_NotFound tests 404 response for unknown IdP.
func TestLogoProxy_NotFound(t *testing.T) {
	metadataStore := caddysamldisco.NewInMemoryMetadataStore([]caddysamldisco.IdPInfo{})
	logoStore := caddysamldisco.NewCachingLogoStore(metadataStore, nil)

	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(metadataStore)
	disco.SetLogoStore(logoStore)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	entityID := url.PathEscape("https://unknown.example.com")
	resp, err := http.Get(server.URL + "/saml/api/logo/" + entityID)
	if err != nil {
		t.Fatalf("GET logo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}
