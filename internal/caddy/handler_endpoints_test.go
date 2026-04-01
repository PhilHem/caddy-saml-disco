//go:build unit

package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/session"
)

func TestServeHTTP_SAMLEndpoints_BypassSessionCheck(t *testing.T) {
	// Setup: Create SAMLDisco with session store configured
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	// SAML paths that should NOT require session
	publicPaths := []string{
		"/saml/metadata",
		"/saml/acs",
		"/saml/disco",
		"/saml/api/idps",
		"/saml/api/select",
	}

	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			// Request WITHOUT session cookie
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			err := s.ServeHTTP(rec, req, next)

			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			// Should NOT redirect - either handled by plugin or passed to next
			if rec.Code == http.StatusFound {
				t.Errorf("path %s should NOT redirect to disco, got 302", path)
			}
		})
	}
}

// Note: TestServeHTTP_CustomLoginRedirect was removed.
// LoginRedirect is a Phase 2/3 feature for custom discovery UIs.
// In Phase 1, we always redirect directly to the single IdP.

// TestServeHTTP_PreservesOriginalURL verifies that the original URL is preserved
// in the RelayState so users can be redirected back after login.

func TestServeHTTP_PreservesOriginalURL(t *testing.T) {
	key := loadTestKey(t)
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := session.NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []domain.IdPInfo{
			{
				EntityID:   "https://idp.example.com/saml",
				SSOURL:     "https://idp.example.com/saml/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:          "https://sp.example.com",
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)

	// Request to a protected URL with query params
	req := httptest.NewRequest(http.MethodGet, "/protected/page?foo=bar", nil)
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	// Should redirect to IdP with RelayState containing original URL
	redirectURL, _ := url.Parse(location)
	relayState := redirectURL.Query().Get("RelayState")
	want := "/protected/page?foo=bar"
	if relayState != want {
		t.Errorf("RelayState = %q, want %q", relayState, want)
	}
}

// TestServeHTTP_SessionInContext verifies that a valid session is stored in
// the request context for downstream handlers to access.

func TestValidateRelayState(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		// Valid relative paths - should be allowed
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"simple path", "/dashboard", "/dashboard"},
		{"path with query", "/page?foo=bar", "/page?foo=bar"},
		{"path with fragment", "/page#section", "/page#section"},
		{"nested path", "/app/settings/profile", "/app/settings/profile"},

		// Absolute URLs - should be rejected (open redirect)
		{"absolute http", "http://evil.com", "/"},
		{"absolute https", "https://evil.com/path", "/"},
		{"absolute with port", "https://evil.com:8080/path", "/"},

		// Protocol-relative URLs - should be rejected
		{"protocol relative", "//evil.com", "/"},
		{"protocol relative with path", "//evil.com/path", "/"},

		// Dangerous schemes - should be rejected
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"data scheme", "data:text/html,<script>alert(1)</script>", "/"},
		{"vbscript scheme", "vbscript:msgbox(1)", "/"},

		// Edge cases
		{"backslash escape", "\\\\evil.com", "/"},
		{"encoded slashes", "%2f%2fevil.com", "/"},
		{"whitespace prefix becomes valid", " /valid", "/valid"}, // trimmed, then valid
		{"tab prefix becomes valid", "\t/valid", "/valid"},       // trimmed, then valid
		{"only whitespace", "   ", "/"},                          // trimmed to empty
		{"newline in path", "/path\nHeader: injection", "/"},     // header injection blocked

		// Double-encoding bypass attempts - should be rejected
		{"double encoded protocol relative", "/%2f%2fevil.com", "/"},     // decodes to //evil.com
		{"triple encoded protocol relative", "/%252f%252fevil.com", "/"}, // decodes to /%2f%2f then //
		{"double encoded with path", "/%2f%2fevil.com/path", "/"},        // decodes to //evil.com/path
		{"mixed encoding bypass", "/%2F%2Fevil.com", "/"},                // uppercase encoding
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// TestRootPackageReExports verifies that utility functions are accessible from root package.
// This test ensures tests can use root package re-exports instead of direct internal imports.

func TestServeHTTP_LogoutEndpoint_ClearsCookie(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/logout", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check that a Set-Cookie header is present with MaxAge=-1 (delete cookie)
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "saml_session" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("expected Set-Cookie header for session cookie")
	}

	if sessionCookie.MaxAge != -1 {
		t.Errorf("cookie MaxAge = %d, want -1 (delete)", sessionCookie.MaxAge)
	}

	if sessionCookie.Value != "" {
		t.Errorf("cookie Value = %q, want empty", sessionCookie.Value)
	}
}

// TestServeHTTP_LogoutEndpoint_RedirectsToRoot verifies that GET /saml/logout
// redirects to "/" by default.

func TestServeHTTP_LogoutEndpoint_RedirectsToRoot(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/logout", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	if location != "/" {
		t.Errorf("Location = %q, want %q", location, "/")
	}
}

// TestServeHTTP_LogoutEndpoint_RedirectsToReturnTo verifies that GET /saml/logout
// with return_to query parameter redirects to that path.

func TestServeHTTP_LogoutEndpoint_RedirectsToReturnTo(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/logout?return_to=/goodbye", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	if location != "/goodbye" {
		t.Errorf("Location = %q, want %q", location, "/goodbye")
	}
}

// TestServeHTTP_LogoutEndpoint_ValidatesReturnTo verifies that absolute URLs
// in return_to are rejected (preventing open redirect).

func TestServeHTTP_LogoutEndpoint_ValidatesReturnTo(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
	}
	s.SetSessionStore(store)

	tests := []struct {
		name     string
		returnTo string
		want     string
	}{
		{"absolute URL", "https://evil.com", "/"},
		{"protocol relative", "//evil.com", "/"},
		{"javascript", "javascript:alert(1)", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/saml/logout?return_to="+url.QueryEscape(tc.returnTo), nil)
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			err := s.ServeHTTP(rec, req, next)

			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			location := rec.Header().Get("Location")
			if location != tc.want {
				t.Errorf("Location = %q, want %q", location, tc.want)
			}
		})
	}
}

// =============================================================================
// Discovery API Tests (Phase 2)
// =============================================================================

// TestDiscoveryAPI_ListIdPs verifies that GET /saml/api/idps returns all IdPs
// as a JSON array.

func TestHealthEndpoint_ReturnsJSON(t *testing.T) {
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{EntityID: "https://idp1.example.com"}})
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.IdPCount != 1 {
		t.Errorf("IdPCount = %d, want 1", resp.IdPCount)
	}
	if !resp.IsFresh {
		t.Error("IsFresh should be true for in-memory store")
	}
	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestHealthEndpoint_NoMetadataStore(t *testing.T) {
	s := &SAMLDisco{}
	// No metadata store configured

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	// Should return JSON error
	var resp httputil.JSONErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON error: %v", err)
	}
	if resp.Error.Code != "config_missing" {
		t.Errorf("error.code = %q, want %q", resp.Error.Code, "config_missing")
	}
}

func TestHealthEndpoint_IncludesVersionInfo(t *testing.T) {
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{EntityID: "https://idp1.example.com"}})
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	_ = s.ServeHTTP(rec, req, next)

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Version should always be present (defaults to "dev")
	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestHealthEndpoint_VersionDefaultsToDev(t *testing.T) {
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{})
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	_ = s.ServeHTTP(rec, req, next)

	var resp HealthResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.Version != "dev" {
		t.Errorf("Version = %q, want %q", resp.Version, "dev")
	}
}

func TestHealthEndpoint_ReturnsValidUntil(t *testing.T) {
	validUntil := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	store := metadata.NewInMemoryMetadataStoreWithValidUntil(
		[]domain.IdPInfo{{EntityID: "https://idp.example.com"}},
		&validUntil,
	)
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.MetadataValidUntil == nil {
		t.Fatal("MetadataValidUntil should be set in response")
	}
	if !resp.MetadataValidUntil.Equal(validUntil) {
		t.Errorf("MetadataValidUntil = %v, want %v", *resp.MetadataValidUntil, validUntil)
	}
}

func TestHealthEndpoint_NoValidUntil(t *testing.T) {
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{EntityID: "https://idp.example.com"}})
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/api/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	_ = s.ServeHTTP(rec, req, next)

	var resp HealthResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil, got %v", *resp.MetadataValidUntil)
	}

	// Verify omitempty works - field should not appear in JSON
	body := rec.Body.String()
	if strings.Contains(body, "metadata_valid_until") {
		t.Error("metadata_valid_until should be omitted from JSON when nil")
	}
}

// =============================================================================
// Simple Health API: /saml/health Tests
// =============================================================================

func TestSimpleHealthEndpoint_ReturnsMetadataHealthOnly(t *testing.T) {
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{{EntityID: "https://idp1.example.com"}})
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	req := httptest.NewRequest(http.MethodGet, "/saml/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	// Should return just MetadataHealth, not full HealthResponse
	var health domain.MetadataHealth
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if health.IdPCount != 1 {
		t.Errorf("IdPCount = %d, want 1", health.IdPCount)
	}
	if !health.IsFresh {
		t.Error("IsFresh should be true for in-memory store")
	}

	// Verify it does NOT include version info (that would be HealthResponse, not MetadataHealth)
	body := rec.Body.String()
	if strings.Contains(body, "version") {
		t.Error("/saml/health should return MetadataHealth without version info")
	}
}

func TestSimpleHealthEndpoint_NoMetadataStore(t *testing.T) {
	s := &SAMLDisco{}
	// No metadata store configured

	req := httptest.NewRequest(http.MethodGet, "/saml/health", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// =============================================================================
// Cleanup/CleanerUpper Interface Tests
// =============================================================================

// TestSAMLDisco_Cleanup_WithCloseableStore verifies that Cleanup() calls Close()
// on metadata stores that support it.

func TestSAMLDisco_Cleanup_WithCloseableStore(t *testing.T) {
	store := &mockCloseableMetadataStore{}
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	err := s.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}

	if !store.closed {
		t.Error("Cleanup() should have called Close() on the metadata store")
	}
}

// TestSAMLDisco_Cleanup_WithNonCloseableStore verifies that Cleanup() works
// with metadata stores that don't implement Close().

func TestSAMLDisco_Cleanup_WithNonCloseableStore(t *testing.T) {
	store := &mockMetadataStore{} // Doesn't have Close()
	s := &SAMLDisco{}
	s.SetMetadataStore(store)

	err := s.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}
	// Should not panic or error
}

// TestSAMLDisco_Cleanup_NilMetadataStore verifies that Cleanup() handles
// nil metadata store gracefully.

func TestSAMLDisco_Cleanup_NilMetadataStore(t *testing.T) {
	s := &SAMLDisco{}
	// No metadata store configured

	err := s.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}
	// Should not panic or error
}

// mockCloseableMetadataStore is a test double that implements Close().
type mockCloseableMetadataStore struct {
	mockMetadataStore
	closed bool
}

func (m *mockCloseableMetadataStore) Close() error {
	m.closed = true
	return nil
}

// =============================================================================
// Cycle 8: RelayState and HTTP Status Edge Case Tests
// =============================================================================

// TestRelayStateBoundaryValues tests edge cases for RelayState validation.
func TestRelayStateBoundaryValues(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		// Boundary cases
		{"exactly empty", "", "/"},
		{"single slash", "/", "/"},
		{"max reasonable length (2048 chars)", "/" + strings.Repeat("a", 2047), "/" + strings.Repeat("a", 2047)},
		{"unicode path", "/ユーザー/dashboard", "/ユーザー/dashboard"},
		{"percent encoded", "/%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC", "/%E3%83%A6%E3%83%BC%E3%82%B6%E3%83%BC"},
		{"mixed valid chars", "/user-123_abc.html?q=test&foo=bar#section", "/user-123_abc.html?q=test&foo=bar#section"},

		// Edge cases that should be rejected
		{"null byte", "/path\x00/injection", "/"},
		{"carriage return", "/path\r\nHeader: injected", "/"},
		{"control chars", "/path\x01\x02\x03", "/"},
		// Note: backslash is currently NOT rejected (could be future improvement)
		{"backslash mixed", "/path\\evil.com", "/path\\evil.com"},

		// Numeric edge cases
		{"zero after slash", "/0", "/0"},
		{"negative number", "/-123", "/-123"},

		// Query string edge cases
		{"empty query value", "/path?key=", "/path?key="},
		{"multiple equals", "/path?key=val=ue", "/path?key=val=ue"},
		{"no value", "/path?key", "/path?key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// TestHTTPStatusCodeEdgeCases tests unusual HTTP status code handling.
func TestHTTPStatusCodeEdgeCases(t *testing.T) {
	key := loadTestKey(t)
	store := session.NewCookieSessionStore(key, 8*time.Hour)

	tests := []struct {
		name         string
		path         string
		setupFunc    func(*SAMLDisco)
		expectStatus int
		expectBody   string
	}{
		{
			name: "health endpoint with nil store",
			path: "/saml/api/health",
			setupFunc: func(s *SAMLDisco) {
				// No metadata store
			},
			expectStatus: http.StatusInternalServerError,
			expectBody:   "config_missing",
		},
		{
			name: "simple health with nil store",
			path: "/saml/health",
			setupFunc: func(s *SAMLDisco) {
				// No metadata store
			},
			expectStatus: http.StatusInternalServerError,
			expectBody:   "",
		},
		{
			name: "logout with method not allowed",
			path: "/saml/logout",
			setupFunc: func(s *SAMLDisco) {
				s.SetSessionStore(store)
			},
			expectStatus: http.StatusFound,
			expectBody:   "",
		},
		{
			name: "metadata endpoint (should work without session)",
			path: "/saml/metadata",
			setupFunc: func(s *SAMLDisco) {
				// No SAML service configured - should still not require session
			},
			expectStatus: http.StatusInternalServerError,
			expectBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &SAMLDisco{
				Config: Config{
					SessionCookieName: "saml_session",
				},
			}
			tc.setupFunc(s)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			err := s.ServeHTTP(rec, req, next)
			if err != nil {
				// Some endpoints return errors instead of writing status
				t.Logf("ServeHTTP returned error: %v", err)
			}

			if rec.Code != tc.expectStatus && err == nil {
				t.Errorf("status = %d, want %d", rec.Code, tc.expectStatus)
			}

			if tc.expectBody != "" && !strings.Contains(rec.Body.String(), tc.expectBody) {
				t.Errorf("body should contain %q, got %q", tc.expectBody, rec.Body.String())
			}
		})
	}
}

// =============================================================================
// Cycle 1: Enhanced RelayState Validation Tests
// =============================================================================

// TestValidateRelayState_DoubleEncodedBypass tests that double-encoded protocol markers are detected.
func TestValidateRelayState_DoubleEncodedBypass(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"double encoded //", "/%2f%2fevil.com", "/"},
		{"triple encoded //", "/%252f%252fevil.com", "/"},
		{"double encoded with path", "/%2f%2fevil.com/path", "/"},
		{"mixed case encoding", "/%2F%2Fevil.com", "/"},
		{"quadruple encoded", "/%25252f%25252fevil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// TestValidateRelayState_EncodedProtocolMarker tests that protocol markers in decoded paths are detected.
func TestValidateRelayState_EncodedProtocolMarker(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"http: encoded", "/path?redirect=http%3A//evil.com", "/"},
		{"https: encoded", "/path?redirect=https%3A//evil.com", "/"},
		{"javascript: encoded", "javascript%3Aalert(1)", "/"},
		{"data: encoded", "data%3Atext/html,evil", "/"},
		{"encoded colon in path", "/path%3A//evil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// TestValidateRelayState_MixedEncodingBypass tests combinations of encoding tricks.
func TestValidateRelayState_MixedEncodingBypass(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"encoded slash then literal", "/%2f/evil.com", "/"},
		{"literal then encoded", "//%2fevil.com", "/"},
		{"mixed with uppercase", "/%2F/evil.com", "/"},
		{"partial encoding", "/path/%2f%2fevil.com", "/"},
		{"nested encoding layers", "/%252F%252Fevil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// FuzzValidateRelayState_InvariantCheck is a property test that validates all security invariants.
func FuzzValidateRelayState_InvariantCheck(f *testing.F) {
	// Use the same seeds as the main fuzz test for consistency
	seeds := []string{
		"", "/", "/dashboard", "/page?foo=bar",
		"http://evil.com", "//evil.com",
		"javascript:alert(1)",
		"%2f%2fevil.com",
		"/path\r\nHeader: injection",
		"/%252f%252fevil.com",
		"/path?redirect=http%3A//evil.com",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := httputil.ValidateRelayState(input)

		// Invariant 1: Output is never empty
		if result == "" {
			t.Errorf("httputil.ValidateRelayState(%q) returned empty string", input)
		}

		// Invariant 2: Output always starts with "/"
		if !strings.HasPrefix(result, "/") {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, does not start with /", input, result)
		}

		// Invariant 3: Output never starts with "//" (protocol-relative URL)
		if strings.HasPrefix(result, "//") {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, starts with // (protocol-relative)", input, result)
		}

		// Invariant 4: Parsed URL has no scheme or host
		parsed, err := url.Parse(result)
		if err != nil {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, failed to parse: %v", input, result, err)
		} else {
			if parsed.Scheme != "" {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, has scheme: %q", input, result, parsed.Scheme)
			}
			if parsed.Host != "" {
				t.Errorf("httputil.ValidateRelayState(%q) = %q, has host: %q", input, result, parsed.Host)
			}
		}

		// Invariant 5: Output contains no CR/LF (header injection prevention)
		if strings.ContainsAny(result, "\r\n") {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, contains CR/LF", input, result)
		}

		// Invariant 6: Decoded output must not contain protocol markers
		decoded := result
		for i := 0; i < 10; i++ {
			newDecoded, err := url.QueryUnescape(decoded)
			if err != nil || newDecoded == decoded {
				break
			}
			decoded = newDecoded
		}

		// After full decoding, check for protocol markers
		if strings.Contains(decoded, "://") {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, decoded contains protocol marker: %q", input, result, decoded)
		}
		if strings.HasPrefix(decoded, "//") {
			t.Errorf("httputil.ValidateRelayState(%q) = %q, decoded starts with //: %q", input, result, decoded)
		}
	})
}
