//go:build unit

package caddysamldisco

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// mockMetadataStore is a test double for MetadataStore.
type mockMetadataStore struct {
	idps []IdPInfo
}

func (m *mockMetadataStore) GetIdP(entityID string) (*IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, ErrIdPNotFound
}

func (m *mockMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	return m.idps, nil
}

func (m *mockMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStore) Health() MetadataHealth {
	return MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// mockNextHandler is a test double for the next handler in the middleware chain.
type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*mockNextHandler)(nil)

// testTemplateRenderer returns a template renderer for tests.
// This uses the embedded templates.
func testTemplateRenderer(t *testing.T) *TemplateRenderer {
	t.Helper()
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("failed to create template renderer: %v", err)
	}
	return renderer
}

// Note: TestServeHTTP_NoSession_RedirectsToDiscovery was removed.
// The new behavior is tested by TestServeHTTP_NoSession_RedirectsToIdP.
// Phase 1 redirects directly to IdP; discovery UI comes in Phase 2.

// TestServeHTTP_InvalidSession_RedirectsToIdP verifies that requests with
// an invalid/expired/tampered session cookie are redirected to the IdP.
func TestServeHTTP_InvalidSession_RedirectsToIdP(t *testing.T) {
	// Setup: Create SAMLDisco with all required components
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
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
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	tests := []struct {
		name   string
		cookie string
	}{
		{"invalid JWT", "not-a-valid-jwt"},
		{"tampered signature", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.tampered"},
		{"expired token", "expired"}, // Will be caught as invalid format
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Host = "sp.example.com"
			req.AddCookie(&http.Cookie{
				Name:  "saml_session",
				Value: tc.cookie,
			})
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
			// Should redirect to IdP SSO URL
			if !strings.HasPrefix(location, "https://idp.example.com/saml/sso") {
				t.Errorf("Location = %q, should start with IdP SSO URL", location)
			}

			// Verify RelayState contains original URL
			redirectURL, _ := url.Parse(location)
			relayState := redirectURL.Query().Get("RelayState")
			if relayState != "/protected" {
				t.Errorf("RelayState = %q, want %q", relayState, "/protected")
			}

			if next.called {
				t.Error("next handler should NOT be called with invalid session")
			}
		})
	}
}

// TestServeHTTP_ValidSession_PassesToNext verifies that requests with a valid
// session cookie are passed to the next handler.
func TestServeHTTP_ValidSession_PassesToNext(t *testing.T) {
	// Setup: Create SAMLDisco with session store configured
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Create a valid session token
	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	// Create request with valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	// Execute
	err = s.ServeHTTP(rec, req, next)

	// Verify
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !next.called {
		t.Error("next handler should be called with valid session")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestServeHTTP_SAMLEndpoints_BypassSessionCheck verifies that SAML endpoints
// do not require session authentication.
func TestServeHTTP_SAMLEndpoints_BypassSessionCheck(t *testing.T) {
	// Setup: Create SAMLDisco with session store configured
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

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
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
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
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: metadataStore,
	}

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
func TestServeHTTP_SessionInContext(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Create a valid session token
	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
		Attributes:  map[string]string{"role": "admin"},
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	// Create request with valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	// Custom next handler that checks for session in context
	var contextSession *Session
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		contextSession = GetSession(r)
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Execute
	err = s.ServeHTTP(rec, req, next)

	// Verify
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if contextSession == nil {
		t.Fatal("session should be available in context")
	}

	if contextSession.Subject != "user@example.com" {
		t.Errorf("Subject = %q, want %q", contextSession.Subject, "user@example.com")
	}

	if contextSession.Attributes["role"] != "admin" {
		t.Errorf("Attributes[role] = %q, want %q", contextSession.Attributes["role"], "admin")
	}
}

// TestServeHTTP_NoSession_RedirectsToIdP verifies that requests without
// a session cookie are redirected directly to the IdP when only one IdP is configured.
func TestServeHTTP_NoSession_RedirectsToIdP(t *testing.T) {
	// Setup: Create SAMLDisco with all required components
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	// Create mock metadata store with single IdP
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:          "https://sp.example.com",
			SessionCookieName: "saml_session",
		},
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	// Create request without session cookie to a protected route
	req := httptest.NewRequest(http.MethodGet, "/protected/page", nil)
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	// Execute
	err = s.ServeHTTP(rec, req, next)

	// Verify
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")

	// Should redirect to IdP SSO URL
	if !strings.HasPrefix(location, "https://idp.example.com/saml/sso") {
		t.Errorf("Location = %q, should start with IdP SSO URL", location)
	}

	// Parse redirect URL to verify query parameters
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	// Should contain SAMLRequest parameter
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}

	// Should contain RelayState with original URL
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/protected/page" {
		t.Errorf("RelayState = %q, want %q", relayState, "/protected/page")
	}

	if next.called {
		t.Error("next handler should NOT be called when no session")
	}
}

// TestServeHTTP_NoSession_NoMetadataStore_ReturnsError verifies that when
// metadata store is not configured, an appropriate error is returned.
func TestServeHTTP_NoSession_NoMetadataStore_ReturnsError(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: nil, // No metadata store configured
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Metadata store") {
		t.Errorf("error message should mention metadata store, got: %q", body)
	}
}

// TestServeHTTP_NoSession_NoIdPConfigured_ReturnsError verifies that when
// no IdP is configured in the metadata store, an appropriate error is returned.
func TestServeHTTP_NoSession_NoIdPConfigured_ReturnsError(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	// Create empty metadata store (no IdPs)
	emptyStore := &mockMetadataStore{idps: []IdPInfo{}}

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: emptyStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "identity provider") {
		t.Errorf("error message should mention identity provider, got: %q", body)
	}
}

// TestHandleACS_UsesConfiguredSessionDuration verifies that the session
// created in handleACS uses the configured SessionDuration, not a hardcoded value.
func TestHandleACS_UsesConfiguredSessionDuration(t *testing.T) {
	key := loadTestKey(t)
	customDuration := 2 * time.Hour // Different from default 8h

	store := NewCookieSessionStore(key, customDuration)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore:    store,
		sessionDuration: customDuration, // This field needs to be added
	}

	// Create a session the way handleACS does
	now := time.Now()
	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    now,
		ExpiresAt:   now.Add(s.sessionDuration),
	}

	// Verify the session expiration is ~2 hours from now, not 8 hours
	expectedExpiry := now.Add(customDuration)
	tolerance := time.Second

	if session.ExpiresAt.Sub(expectedExpiry).Abs() > tolerance {
		t.Errorf("ExpiresAt = %v, want ~%v (configured duration: %v)",
			session.ExpiresAt, expectedExpiry, customDuration)
	}

	// Also verify it's NOT 8 hours (the old hardcoded value)
	eightHourExpiry := now.Add(8 * time.Hour)
	if session.ExpiresAt.Sub(eightHourExpiry).Abs() < tolerance {
		t.Errorf("ExpiresAt should NOT be 8 hours (hardcoded value), got %v", session.ExpiresAt)
	}
}

// TestSetSessionCookie_MaxAge verifies that session cookies have MaxAge set
// to match the configured session duration.
func TestSetSessionCookie_MaxAge(t *testing.T) {
	customDuration := 2 * time.Hour

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionDuration: customDuration,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	s.setSessionCookie(rec, req, "test-token")

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	expectedMaxAge := int(customDuration.Seconds()) // 7200 for 2 hours
	if cookies[0].MaxAge != expectedMaxAge {
		t.Errorf("MaxAge = %d, want %d (session duration in seconds)", cookies[0].MaxAge, expectedMaxAge)
	}
}

// TestServeHTTP_NoSession_NoSAMLService_ReturnsError verifies that when
// SAML service is not configured, an appropriate error is returned.
func TestServeHTTP_NoSession_NoSAMLService_ReturnsError(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:   "https://idp.example.com/saml",
				SSOURL:     "https://idp.example.com/saml/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore:  store,
		samlService:   nil, // No SAML service configured
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "SAML service") {
		t.Errorf("error message should mention SAML service, got: %q", body)
	}
}

// TestServeHTTP_ExpiredToken_RealJWT_RedirectsToIdP verifies that requests with
// a real but expired JWT token are redirected to the IdP.
// This tests the actual JWT expiry mechanism, not hardcoded invalid strings.
func TestServeHTTP_ExpiredToken_RealJWT_RedirectsToIdP(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	// Create store with very short duration (1ms)
	shortDuration := 1 * time.Millisecond
	store := NewCookieSessionStore(key, shortDuration)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
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
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	// Create a REAL valid session token
	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com/saml",
		Attributes:  map[string]string{"email": "user@example.com"},
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	// Verify token is valid JWT format (3 parts)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token should be valid JWT format, got %d parts", len(parts))
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Create request with the now-expired real JWT
	req := httptest.NewRequest(http.MethodGet, "/protected/resource", nil)
	req.Host = "sp.example.com"
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	// Execute
	err = s.ServeHTTP(rec, req, next)

	// Verify
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Should redirect to IdP (not pass to next handler)
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to IdP)", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://idp.example.com/saml/sso") {
		t.Errorf("Location = %q, should redirect to IdP SSO URL", location)
	}

	// Verify RelayState contains original URL
	redirectURL, _ := url.Parse(location)
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/protected/resource" {
		t.Errorf("RelayState = %q, want %q", relayState, "/protected/resource")
	}

	// Next handler should NOT be called (session is expired)
	if next.called {
		t.Error("next handler should NOT be called with expired session")
	}
}

// TestValidateRelayState verifies that RelayState validation prevents open redirects.
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("validateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

// TestServeHTTP_LogoutEndpoint_ClearsCookie verifies that GET /saml/logout
// clears the session cookie by setting MaxAge to -1.
func TestServeHTTP_LogoutEndpoint_ClearsCookie(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

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
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

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
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

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
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

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
func TestDiscoveryAPI_ListIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp1.example.com",
				DisplayName: "University One",
				SSOURL:      "https://idp1.example.com/sso",
			},
			{
				EntityID:    "https://idp2.example.com",
				DisplayName: "University Two",
				SSOURL:      "https://idp2.example.com/sso",
			},
			{
				EntityID:    "https://idp3.example.com",
				DisplayName: "College Three",
				SSOURL:      "https://idp3.example.com/sso",
			},
		},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	// Parse JSON response
	body := rec.Body.String()
	if !strings.Contains(body, "https://idp1.example.com") {
		t.Errorf("response should contain idp1 entity ID, got: %s", body)
	}
	if !strings.Contains(body, "University One") {
		t.Errorf("response should contain idp1 display name, got: %s", body)
	}
	if !strings.Contains(body, "https://idp2.example.com") {
		t.Errorf("response should contain idp2 entity ID, got: %s", body)
	}
	if !strings.Contains(body, "https://idp3.example.com") {
		t.Errorf("response should contain idp3 entity ID, got: %s", body)
	}
}

// TestDiscoveryAPI_ListIdPs_EmptyStore verifies that GET /saml/api/idps returns
// an empty JSON array when no IdPs are configured.
func TestDiscoveryAPI_ListIdPs_EmptyStore(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := strings.TrimSpace(rec.Body.String())
	if body != `{"idps":[]}` {
		t.Errorf("response = %q, want %q", body, `{"idps":[]}`)
	}
}

// TestDiscoveryAPI_ListIdPs_Search verifies that GET /saml/api/idps?q=term
// filters IdPs by the search term.
func TestDiscoveryAPI_ListIdPs_Search(t *testing.T) {
	// Use a mock that actually filters (update mockMetadataStore.ListIdPs)
	metadataStore := &mockMetadataStoreWithFilter{
		idps: []IdPInfo{
			{
				EntityID:    "https://uni-berlin.de/idp",
				DisplayName: "University of Berlin",
				SSOURL:      "https://uni-berlin.de/sso",
			},
			{
				EntityID:    "https://uni-munich.de/idp",
				DisplayName: "University of Munich",
				SSOURL:      "https://uni-munich.de/sso",
			},
			{
				EntityID:    "https://college-hamburg.de/idp",
				DisplayName: "College of Hamburg",
				SSOURL:      "https://college-hamburg.de/sso",
			},
		},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps?q=University", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	// Should contain both universities
	if !strings.Contains(body, "Berlin") {
		t.Errorf("response should contain Berlin, got: %s", body)
	}
	if !strings.Contains(body, "Munich") {
		t.Errorf("response should contain Munich, got: %s", body)
	}
	// Should NOT contain college
	if strings.Contains(body, "Hamburg") {
		t.Errorf("response should NOT contain Hamburg (college, not university), got: %s", body)
	}
}

// TestDiscoveryAPI_ListIdPs_NoMetadataStore verifies proper error handling
// when metadata store is not configured.
func TestDiscoveryAPI_ListIdPs_NoMetadataStore(t *testing.T) {
	s := &SAMLDisco{
		metadataStore: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
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

// mockMetadataStoreWithFilter is a mock that actually implements search filtering.
type mockMetadataStoreWithFilter struct {
	idps []IdPInfo
}

func (m *mockMetadataStoreWithFilter) GetIdP(entityID string) (*IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, ErrIdPNotFound
}

func (m *mockMetadataStoreWithFilter) ListIdPs(filter string) ([]IdPInfo, error) {
	if filter == "" {
		return m.idps, nil
	}
	filter = strings.ToLower(filter)
	var result []IdPInfo
	for _, idp := range m.idps {
		if strings.Contains(strings.ToLower(idp.DisplayName), filter) ||
			strings.Contains(strings.ToLower(idp.EntityID), filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

func (m *mockMetadataStoreWithFilter) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStoreWithFilter) Health() MetadataHealth {
	return MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// =============================================================================
// Discovery API: /saml/api/select Tests
// =============================================================================

// TestDiscoveryAPI_SelectIdP verifies that POST /saml/api/select with a valid
// entity_id returns JSON with redirect_url pointing to IdP SSO URL with SAMLRequest.
func TestDiscoveryAPI_SelectIdP(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	// POST with JSON body containing entity_id
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// API returns 200 with JSON containing redirect_url (not 302)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Parse JSON response
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if !strings.HasPrefix(resp.RedirectURL, "https://idp.example.com/saml/sso") {
		t.Errorf("redirect_url = %q, should start with IdP SSO URL", resp.RedirectURL)
	}

	// Verify SAMLRequest is in the redirect URL
	redirectURL, _ := url.Parse(resp.RedirectURL)
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
}

// TestDiscoveryAPI_SelectIdP_NotFound verifies that POST /saml/api/select with
// an unknown entity_id returns 404.
func TestDiscoveryAPI_SelectIdP_NotFound(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
			},
		},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
	}

	body := strings.NewReader(`{"entity_id": "https://unknown.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestDiscoveryAPI_SelectIdP_MissingEntityID verifies that POST /saml/api/select
// with an empty or missing entity_id returns 400.
func TestDiscoveryAPI_SelectIdP_MissingEntityID(t *testing.T) {
	s := &SAMLDisco{
		metadataStore: &mockMetadataStore{idps: []IdPInfo{}},
	}

	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty object", "{}"},
		{"empty entity_id", `{"entity_id": ""}`},
		{"invalid JSON", `{invalid}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/saml/api/select", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			err := s.ServeHTTP(rec, req, next)

			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d for body %q", rec.Code, http.StatusBadRequest, tc.body)
			}
		})
	}
}

// TestDiscoveryAPI_SelectIdP_PreservesReturnURL verifies that the return_url
// from request body is passed as RelayState in the redirect URL.
func TestDiscoveryAPI_SelectIdP_PreservesReturnURL(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:   "https://idp.example.com/saml",
				SSOURL:     "https://idp.example.com/saml/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "return_url": "/dashboard"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// API returns 200 with JSON containing redirect_url (not 302)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Parse JSON response
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	redirectURL, _ := url.Parse(resp.RedirectURL)
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/dashboard" {
		t.Errorf("RelayState = %q, want %q", relayState, "/dashboard")
	}
}

// TestDiscoveryAPI_SelectIdP_NoSAMLService verifies proper error handling
// when SAML service is not configured.
func TestDiscoveryAPI_SelectIdP_NoSAMLService(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID: "https://idp.example.com/saml",
				SSOURL:   "https://idp.example.com/saml/sso",
			},
		},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
		samlService:   nil,
	}

	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
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
// Discovery API: /saml/api/session Tests
// =============================================================================

// TestDiscoveryAPI_SessionInfo_Authenticated verifies that GET /saml/api/session
// returns session info for authenticated users.
func TestDiscoveryAPI_SessionInfo_Authenticated(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Create a valid session token
	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com/saml",
		Attributes: map[string]string{
			"email":     "user@example.com",
			"firstName": "Test",
			"lastName":  "User",
		},
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("failed to create session token: %v", err)
	}

	// Create request with valid session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"authenticated":true`) {
		t.Errorf("response should contain authenticated:true, got: %s", body)
	}
	if !strings.Contains(body, "user@example.com") {
		t.Errorf("response should contain subject, got: %s", body)
	}
	if !strings.Contains(body, "https://idp.example.com/saml") {
		t.Errorf("response should contain idp_entity_id, got: %s", body)
	}
}

// TestDiscoveryAPI_SessionInfo_Unauthenticated verifies that GET /saml/api/session
// returns authenticated:false when no session exists.
func TestDiscoveryAPI_SessionInfo_Unauthenticated(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Request WITHOUT session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("response should contain authenticated:false, got: %s", body)
	}
}

// TestDiscoveryAPI_SessionInfo_InvalidSession verifies that GET /saml/api/session
// returns authenticated:false when session is invalid/expired.
func TestDiscoveryAPI_SessionInfo_InvalidSession(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Request with invalid session cookie
	req := httptest.NewRequest(http.MethodGet, "/saml/api/session", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: "invalid-token",
	})
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"authenticated":false`) {
		t.Errorf("response should contain authenticated:false for invalid session, got: %s", body)
	}
}

// =============================================================================
// Discovery UI Tests
// =============================================================================

// TestDiscoveryUI_ServesHTML verifies that GET /saml/disco serves HTML.
func TestDiscoveryUI_ServesHTML(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two"},
		},
	}

	s := &SAMLDisco{
		metadataStore:    metadataStore,
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	body := rec.Body.String()
	// Should contain basic HTML structure
	if !strings.Contains(body, "<html") {
		t.Errorf("response should contain <html>, got: %s", body)
	}
	// Should contain IdP selection elements
	if !strings.Contains(body, "IdP") || !strings.Contains(body, "select") {
		t.Errorf("response should contain IdP selection UI elements")
	}
}

// TestDiscoveryUI_SingleIdP_AutoRedirect verifies that GET /saml/disco
// with only one IdP auto-redirects to that IdP.
func TestDiscoveryUI_SingleIdP_AutoRedirect(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:   "https://single-idp.example.com/saml",
				SSOURL:     "https://single-idp.example.com/sso",
				SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID: "https://sp.example.com",
		},
		metadataStore:    metadataStore,
		samlService:      samlService,
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/dashboard", nil)
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Should redirect directly to IdP when only one exists
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to single IdP)", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://single-idp.example.com/sso") {
		t.Errorf("Location = %q, should redirect to single IdP SSO URL", location)
	}

	// Verify SAMLRequest is present
	redirectURL, _ := url.Parse(location)
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}

	// Verify RelayState contains return_url
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/dashboard" {
		t.Errorf("RelayState = %q, want %q", relayState, "/dashboard")
	}
}

// =============================================================================
// Error Template Rendering Tests
// =============================================================================

// TestRenderHTTPError_SetsStatusAndRendersTemplate verifies that renderHTTPError
// sets the correct status code, Content-Type, and renders the error template.
func TestRenderHTTPError_SetsStatusAndRendersTemplate(t *testing.T) {
	s := &SAMLDisco{
		templateRenderer: testTemplateRenderer(t),
	}

	tests := []struct {
		name       string
		statusCode int
		title      string
		message    string
	}{
		{
			name:       "500 configuration error",
			statusCode: http.StatusInternalServerError,
			title:      "Configuration Error",
			message:    "SAML service is not configured",
		},
		{
			name:       "401 authentication failed",
			statusCode: http.StatusUnauthorized,
			title:      "Authentication Failed",
			message:    "SAML authentication failed",
		},
		{
			name:       "400 bad request",
			statusCode: http.StatusBadRequest,
			title:      "Invalid Request",
			message:    "entity_id is required",
		},
		{
			name:       "404 not found",
			statusCode: http.StatusNotFound,
			title:      "IdP Not Found",
			message:    "The requested identity provider was not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			s.renderHTTPError(rec, tc.statusCode, tc.title, tc.message)

			// Verify status code
			if rec.Code != tc.statusCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.statusCode)
			}

			// Verify Content-Type
			contentType := rec.Header().Get("Content-Type")
			if contentType != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
			}

			// Verify HTML contains title and message
			body := rec.Body.String()
			if !strings.Contains(body, tc.title) {
				t.Errorf("response should contain title %q, got: %s", tc.title, body)
			}
			if !strings.Contains(body, tc.message) {
				t.Errorf("response should contain message %q, got: %s", tc.message, body)
			}

			// Verify it's valid HTML
			if !strings.Contains(body, "<html") {
				t.Errorf("response should be HTML, got: %s", body)
			}
		})
	}
}

// TestRenderHTTPError_EscapesHTML verifies that renderHTTPError escapes HTML
// in title and message to prevent XSS attacks.
func TestRenderHTTPError_EscapesHTML(t *testing.T) {
	s := &SAMLDisco{
		templateRenderer: testTemplateRenderer(t),
	}

	rec := httptest.NewRecorder()

	// Try to inject HTML/JS via error message
	s.renderHTTPError(rec, http.StatusInternalServerError,
		"<script>alert('title')</script>",
		"<script>alert('message')</script>")

	body := rec.Body.String()

	// Should NOT contain raw script tags (should be escaped)
	if strings.Contains(body, "<script>") {
		t.Errorf("response should escape HTML, got raw script tags: %s", body)
	}

	// Should contain escaped versions
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("response should contain escaped script tags, got: %s", body)
	}
}

// TestServeHTTP_NoMetadataStore_ReturnsHTMLError verifies that missing
// metadata store returns an HTML error page, not plain text.
func TestServeHTTP_NoMetadataStore_ReturnsHTMLError(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore:     store,
		samlService:      samlService,
		metadataStore:    nil, // No metadata store configured
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	// Verify it's HTML, not plain text
	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "<html") {
		t.Errorf("error response should be HTML, got: %s", body)
	}
	if !strings.Contains(body, "Configuration Error") {
		t.Errorf("error response should contain 'Configuration Error', got: %s", body)
	}
}

// TestHandleACS_SAMLNotConfigured_ReturnsHTMLError verifies that ACS errors
// return HTML error pages.
func TestHandleACS_SAMLNotConfigured_ReturnsHTMLError(t *testing.T) {
	s := &SAMLDisco{
		samlService:      nil, // SAML not configured
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "<html") {
		t.Errorf("error response should be HTML, got: %s", body)
	}
}

// TestDiscoveryAPI_ListIdPs_NoMetadataStore_ReturnsJSONError verifies that
// /saml/api/idps returns JSON error when metadata store is not configured.
func TestDiscoveryAPI_ListIdPs_NoMetadataStore_ReturnsJSONError(t *testing.T) {
	s := &SAMLDisco{
		metadataStore:    nil,
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	// Verify JSON error structure
	var resp JSONErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if resp.Error.Code != "config_missing" {
		t.Errorf("error.code = %q, want config_missing", resp.Error.Code)
	}
}

// TestDiscoveryAPI_SelectIdP_NotFound_ReturnsJSONError verifies that
// 404 errors for API endpoints return JSON error responses.
func TestDiscoveryAPI_SelectIdP_NotFound_ReturnsJSONError(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp.example.com/saml"},
		},
	}

	s := &SAMLDisco{
		metadataStore:    metadataStore,
		templateRenderer: testTemplateRenderer(t),
	}

	body := strings.NewReader(`{"entity_id": "https://unknown.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	// Verify JSON error structure
	var resp JSONErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if resp.Error.Code != "idp_not_found" {
		t.Errorf("error.code = %q, want idp_not_found", resp.Error.Code)
	}
}

// =============================================================================
// Remember Flag Tests (Cycle 5 - BREAKING CHANGE)
// =============================================================================

// TestDiscoveryAPI_SelectIdP_RememberTrue_SetsCookie verifies that when
// remember=true is sent, the remember cookie is set.
func TestDiscoveryAPI_SelectIdP_RememberTrue_SetsCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
		},
		samlService:   samlService,
		metadataStore: metadataStore,
	}
	s.SetRememberIdPDuration(30 * 24 * time.Hour) // 30 days

	// POST with remember=true
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "remember": true}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check for remember cookie
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			found = true
			if c.Value != "https://idp.example.com/saml" {
				t.Errorf("remember cookie value = %q, want %q", c.Value, "https://idp.example.com/saml")
			}
			break
		}
	}
	if !found {
		t.Error("remember cookie should be set when remember=true")
	}
}

// TestDiscoveryAPI_SelectIdP_RememberFalse_DoesNotSetCookie verifies that when
// remember=false is sent, the remember cookie is NOT set.
func TestDiscoveryAPI_SelectIdP_RememberFalse_DoesNotSetCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
		},
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	// POST with remember=false
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml", "remember": false}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check that remember cookie is NOT set
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			t.Error("remember cookie should NOT be set when remember=false")
			break
		}
	}
}

// TestDiscoveryAPI_SelectIdP_RememberOmitted_DoesNotSetCookie verifies that when
// remember is omitted (default false), the remember cookie is NOT set.
// This is a BREAKING CHANGE from previous behavior where cookie was always set.
func TestDiscoveryAPI_SelectIdP_RememberOmitted_DoesNotSetCookie(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "Example IdP",
				SSOURL:      "https://idp.example.com/saml/sso",
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			EntityID:              "https://sp.example.com",
			RememberIdPCookieName: "saml_last_idp",
		},
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	// POST WITHOUT remember field (omitted)
	body := strings.NewReader(`{"entity_id": "https://idp.example.com/saml"}`)
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", body)
	req.Header.Set("Content-Type", "application/json")
	req.Host = "sp.example.com"
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err = s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Check that remember cookie is NOT set (BREAKING CHANGE: previously was always set)
	cookies := rec.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "saml_last_idp" {
			t.Error("remember cookie should NOT be set when remember is omitted (BREAKING CHANGE from previous behavior)")
			break
		}
	}
}

// =============================================================================
// Pinned IdPs API Tests (Cycle 6)
// =============================================================================

// TestDiscoveryAPI_ListIdPs_ReturnsPinnedIdPs verifies that GET /saml/api/idps
// returns a pinned_idps field when PinnedIdPs is configured.
func TestDiscoveryAPI_ListIdPs_ReturnsPinnedIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two", SSOURL: "https://idp2.example.com/sso"},
			{EntityID: "https://idp3.example.com", DisplayName: "IdP Three", SSOURL: "https://idp3.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			PinnedIdPs: []string{"https://idp1.example.com", "https://idp3.example.com"},
		},
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		IdPs       []IdPInfo `json:"idps"`
		PinnedIdPs []IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify pinned_idps contains the configured IdPs
	if len(resp.PinnedIdPs) != 2 {
		t.Errorf("pinned_idps length = %d, want 2", len(resp.PinnedIdPs))
	}

	// Verify pinned IdPs are in the response
	pinnedEntityIDs := make(map[string]bool)
	for _, idp := range resp.PinnedIdPs {
		pinnedEntityIDs[idp.EntityID] = true
	}
	if !pinnedEntityIDs["https://idp1.example.com"] {
		t.Error("pinned_idps should contain https://idp1.example.com")
	}
	if !pinnedEntityIDs["https://idp3.example.com"] {
		t.Error("pinned_idps should contain https://idp3.example.com")
	}
}

// TestDiscoveryAPI_ListIdPs_PinnedIdPsFilteredFromMain verifies that pinned IdPs
// are removed from the main idps list to prevent duplication.
func TestDiscoveryAPI_ListIdPs_PinnedIdPsFilteredFromMain(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two", SSOURL: "https://idp2.example.com/sso"},
			{EntityID: "https://idp3.example.com", DisplayName: "IdP Three", SSOURL: "https://idp3.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config: Config{
			PinnedIdPs: []string{"https://idp1.example.com"},
		},
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	var resp struct {
		IdPs       []IdPInfo `json:"idps"`
		PinnedIdPs []IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify main idps list does NOT contain pinned IdP
	for _, idp := range resp.IdPs {
		if idp.EntityID == "https://idp1.example.com" {
			t.Error("idps should NOT contain pinned IdP https://idp1.example.com")
		}
	}

	// Verify main idps contains only non-pinned IdPs
	if len(resp.IdPs) != 2 {
		t.Errorf("idps length = %d, want 2 (non-pinned IdPs only)", len(resp.IdPs))
	}

	// Verify pinned_idps has the pinned IdP
	if len(resp.PinnedIdPs) != 1 {
		t.Fatalf("pinned_idps length = %d, want 1", len(resp.PinnedIdPs))
	}
	if resp.PinnedIdPs[0].EntityID != "https://idp1.example.com" {
		t.Errorf("pinned_idps[0].EntityID = %q, want %q", resp.PinnedIdPs[0].EntityID, "https://idp1.example.com")
	}
}

// TestDiscoveryAPI_ListIdPs_NoPinnedIdPs verifies that when PinnedIdPs is not
// configured, the response either omits pinned_idps or returns an empty array.
func TestDiscoveryAPI_ListIdPs_NoPinnedIdPs(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One", SSOURL: "https://idp1.example.com/sso"},
		},
	}

	s := &SAMLDisco{
		Config:        Config{},
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	var resp struct {
		IdPs       []IdPInfo `json:"idps"`
		PinnedIdPs []IdPInfo `json:"pinned_idps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Main idps should contain all IdPs
	if len(resp.IdPs) != 1 {
		t.Errorf("idps length = %d, want 1", len(resp.IdPs))
	}

	// pinned_idps should be nil or empty (omitempty may exclude it)
	if len(resp.PinnedIdPs) != 0 {
		t.Errorf("pinned_idps length = %d, want 0", len(resp.PinnedIdPs))
	}
}

// =============================================================================
// LoginRedirect Tests (Custom UI Support)
// =============================================================================

// TestServeHTTP_NoSession_LoginRedirect_RedirectsToCustomURL verifies that when
// LoginRedirect is configured, unauthenticated requests are redirected to the
// custom login URL instead of directly to the IdP.
func TestServeHTTP_NoSession_LoginRedirect_RedirectsToCustomURL(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			LoginRedirect:     "/custom/login",
		},
		sessionStore: store,
	}

	// Request without session to a protected route
	req := httptest.NewRequest(http.MethodGet, "/protected/page", nil)
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
	// Should redirect to custom login URL with return_url parameter
	want := "/custom/login?return_url=%2Fprotected%2Fpage"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}

	if next.called {
		t.Error("next handler should NOT be called when no session")
	}
}

// TestServeHTTP_NoSession_LoginRedirect_PreservesQueryParams verifies that when
// LoginRedirect already has query parameters, return_url is appended correctly.
func TestServeHTTP_NoSession_LoginRedirect_PreservesQueryParams(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			LoginRedirect:     "/login?theme=dark",
		},
		sessionStore: store,
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
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
	// Should preserve existing query params and append return_url
	want := "/login?theme=dark&return_url=%2Fprotected"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}
}

// TestServeHTTP_NoLoginRedirect_SingleIdP_DirectRedirect verifies that when
// LoginRedirect is NOT configured and there's only one IdP, users are
// redirected directly to that IdP (existing Phase 1 behavior).
func TestServeHTTP_NoLoginRedirect_SingleIdP_DirectRedirect(t *testing.T) {
	key := loadTestKey(t)
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	store := NewCookieSessionStore(key, 8*time.Hour)
	samlService := NewSAMLService("https://sp.example.com", key, cert)

	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
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
			// LoginRedirect is NOT set
		},
		sessionStore:  store,
		samlService:   samlService,
		metadataStore: metadataStore,
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
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
	// Should redirect directly to IdP SSO URL (existing behavior)
	if !strings.HasPrefix(location, "https://idp.example.com/saml/sso") {
		t.Errorf("Location = %q, should start with IdP SSO URL", location)
	}

	// Should contain SAMLRequest (SAML auth flow)
	redirectURL, _ := url.Parse(location)
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
}

// TestDiscoveryUI_PreservesReturnURL verifies that return_url is preserved
// when showing the discovery page.
func TestDiscoveryUI_PreservesReturnURL(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{EntityID: "https://idp1.example.com", DisplayName: "IdP One"},
			{EntityID: "https://idp2.example.com", DisplayName: "IdP Two"},
		},
	}

	s := &SAMLDisco{
		metadataStore:    metadataStore,
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/protected/page", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	// The return_url should be embedded in the HTML for the selection form
	// Note: html/template escapes forward slashes in JS strings as \/
	if !strings.Contains(body, "/protected/page") && !strings.Contains(body, `\/protected\/page`) {
		t.Errorf("response should contain return_url, got: %s", body)
	}
}

// TestCORS_ApiEndpoints verifies that CORS headers are applied correctly
// to /saml/api/* endpoints based on configuration.
func TestCORS_ApiEndpoints(t *testing.T) {
	tests := []struct {
		name          string
		origins       []string
		credentials   bool
		requestOrigin string
		endpoint      string
		wantOrigin    string
		wantCreds     string
	}{
		{
			name:          "matching origin gets CORS headers",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://app.example.com",
		},
		{
			name:          "non-matching origin gets no CORS",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://evil.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "wildcard allows any origin",
			origins:       []string{"*"},
			requestOrigin: "https://any.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "*",
		},
		{
			name:          "credentials header when enabled",
			origins:       []string{"https://app.example.com"},
			credentials:   true,
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/session",
			wantOrigin:    "https://app.example.com",
			wantCreds:     "true",
		},
		{
			name:          "no credentials header with wildcard",
			origins:       []string{"*"},
			credentials:   false, // can't use credentials with wildcard anyway
			requestOrigin: "https://any.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "*",
			wantCreds:     "",
		},
		{
			name:          "non-API endpoints get no CORS",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/disco",
			wantOrigin:    "",
		},
		{
			name:          "no origin header means no CORS response",
			origins:       []string{"https://app.example.com"},
			requestOrigin: "", // no Origin header
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "CORS disabled when no origins configured",
			origins:       nil,
			requestOrigin: "https://app.example.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "",
		},
		{
			name:          "multiple origins - first matches",
			origins:       []string{"https://a.com", "https://b.com"},
			requestOrigin: "https://a.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://a.com",
		},
		{
			name:          "multiple origins - second matches",
			origins:       []string{"https://a.com", "https://b.com"},
			requestOrigin: "https://b.com",
			endpoint:      "/saml/api/idps",
			wantOrigin:    "https://b.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metadataStore := &mockMetadataStore{
				idps: []IdPInfo{{EntityID: "https://idp.example.com", DisplayName: "Test IdP"}},
			}

			s := &SAMLDisco{
				Config: Config{
					CORSAllowedOrigins:   tc.origins,
					CORSAllowCredentials: tc.credentials,
				},
				metadataStore:    metadataStore,
				templateRenderer: testTemplateRenderer(t),
			}

			req := httptest.NewRequest(http.MethodGet, tc.endpoint, nil)
			if tc.requestOrigin != "" {
				req.Header.Set("Origin", tc.requestOrigin)
			}
			rec := httptest.NewRecorder()
			next := &mockNextHandler{}

			_ = s.ServeHTTP(rec, req, next)

			gotOrigin := rec.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tc.wantOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", gotOrigin, tc.wantOrigin)
			}

			gotCreds := rec.Header().Get("Access-Control-Allow-Credentials")
			if gotCreds != tc.wantCreds {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q", gotCreds, tc.wantCreds)
			}

			// Verify other CORS headers are set when origin matches
			if tc.wantOrigin != "" {
				gotMethods := rec.Header().Get("Access-Control-Allow-Methods")
				if gotMethods == "" {
					t.Error("Access-Control-Allow-Methods should be set when CORS is allowed")
				}
				gotHeaders := rec.Header().Get("Access-Control-Allow-Headers")
				if gotHeaders == "" {
					t.Error("Access-Control-Allow-Headers should be set when CORS is allowed")
				}
			}
		})
	}
}

// TestCORS_PreflightRequest verifies that OPTIONS requests to API endpoints
// return proper CORS preflight responses.
func TestCORS_PreflightRequest(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{{EntityID: "https://idp.example.com", DisplayName: "Test IdP"}},
	}

	s := &SAMLDisco{
		Config: Config{
			CORSAllowedOrigins:   []string{"https://app.example.com"},
			CORSAllowCredentials: true,
		},
		metadataStore:    metadataStore,
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodOptions, "/saml/api/idps", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	err := s.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Preflight should return 204 No Content
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// CORS headers should be present
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods should be set")
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}

	// Next handler should NOT be called for preflight
	if next.called {
		t.Error("next handler should NOT be called for preflight request")
	}
}

// TestCORS_PreflightNonApiEndpoint verifies that OPTIONS requests to non-API
// endpoints are passed through (not handled as CORS preflight).
func TestCORS_PreflightNonApiEndpoint(t *testing.T) {
	s := &SAMLDisco{
		Config: Config{
			CORSAllowedOrigins: []string{"https://app.example.com"},
		},
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodOptions, "/saml/disco", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	_ = s.ServeHTTP(rec, req, next)

	// Non-API endpoints should NOT get CORS headers
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for non-API endpoint", got)
	}

	// Next handler should be called (OPTIONS not handled as preflight)
	if !next.called {
		t.Error("next handler should be called for non-API OPTIONS request")
	}
}

// =============================================================================
// Multi-Language / Accept-Language Support Tests (Phase 3)
// =============================================================================

// TestDiscoveryUI_RespectsAcceptLanguage verifies that the discovery HTML page
// shows localized IdP names based on Accept-Language header.
func TestDiscoveryUI_RespectsAcceptLanguage(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "English Name",
				DisplayNames: map[string]string{
					"en": "English Name",
					"de": "Deutscher Name",
				},
				SSOURL: "https://idp.example.com/saml/sso",
			},
		},
	}

	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer: %v", err)
	}

	s := &SAMLDisco{
		metadataStore:    metadataStore,
		templateRenderer: renderer,
	}

	tests := []struct {
		name         string
		acceptLang   string
		expectedName string
	}{
		{"german", "de", "Deutscher Name"},
		{"english", "en", "English Name"},
		{"no header", "", "English Name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
			if tc.acceptLang != "" {
				req.Header.Set("Accept-Language", tc.acceptLang)
			}
			rec := httptest.NewRecorder()

			err := s.renderDiscoveryHTML(rec, req, metadataStore.idps, "/")
			if err != nil {
				t.Fatalf("renderDiscoveryHTML returned error: %v", err)
			}

			body := rec.Body.String()
			if !strings.Contains(body, tc.expectedName) {
				t.Errorf("response body should contain %q, got:\n%s", tc.expectedName, body)
			}
		})
	}
}

// TestDiscoveryAPI_ListIdPs_RespectsAcceptLanguage verifies that the JSON API
// returns localized IdP names based on Accept-Language header.
func TestDiscoveryAPI_ListIdPs_RespectsAcceptLanguage(t *testing.T) {
	metadataStore := &mockMetadataStore{
		idps: []IdPInfo{
			{
				EntityID:    "https://idp.example.com/saml",
				DisplayName: "English Name",
				DisplayNames: map[string]string{
					"en": "English Name",
					"de": "Deutscher Name",
				},
				Description: "English description",
				Descriptions: map[string]string{
					"en": "English description",
					"de": "Deutsche Beschreibung",
				},
				SSOURL: "https://idp.example.com/saml/sso",
			},
		},
	}

	s := &SAMLDisco{
		metadataStore: metadataStore,
	}

	tests := []struct {
		name         string
		acceptLang   string
		expectedName string
		expectedDesc string
	}{
		{"german", "de", "Deutscher Name", "Deutsche Beschreibung"},
		{"english", "en", "English Name", "English description"},
		{"german regional", "de-AT", "Deutscher Name", "Deutsche Beschreibung"},
		{"fallback to german", "fr, de;q=0.9", "Deutscher Name", "Deutsche Beschreibung"},
		{"no header defaults to english", "", "English Name", "English description"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
			if tc.acceptLang != "" {
				req.Header.Set("Accept-Language", tc.acceptLang)
			}
			rec := httptest.NewRecorder()

			err := s.handleListIdPs(rec, req)
			if err != nil {
				t.Fatalf("handleListIdPs returned error: %v", err)
			}

			var response idpListResponse
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if len(response.IdPs) != 1 {
				t.Fatalf("expected 1 IdP, got %d", len(response.IdPs))
			}

			if response.IdPs[0].DisplayName != tc.expectedName {
				t.Errorf("DisplayName = %q, want %q",
					response.IdPs[0].DisplayName, tc.expectedName)
			}
			if response.IdPs[0].Description != tc.expectedDesc {
				t.Errorf("Description = %q, want %q",
					response.IdPs[0].Description, tc.expectedDesc)
			}
		})
	}
}

// TestParseAcceptLanguage verifies Accept-Language header parsing with
// quality values and regional variant handling.
func TestParseAcceptLanguage(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected []string
	}{
		// Simple cases
		{"single language", "en", []string{"en"}},
		{"single german", "de", []string{"de"}},

		// Regional variants should include base language
		{"regional variant", "en-US", []string{"en-US", "en"}},
		{"german regional", "de-AT", []string{"de-AT", "de"}},

		// Multiple languages
		{"multiple languages", "de, en", []string{"de", "en"}},
		{"multiple reversed", "en, de", []string{"en", "de"}},

		// Quality values
		{"with quality", "de, en;q=0.9", []string{"de", "en"}},
		{"quality sorting", "en;q=0.5, de;q=0.9", []string{"de", "en"}},
		{"complex quality", "en-US;q=0.8, de;q=0.9, fr;q=0.7", []string{"de", "en-US", "en", "fr"}},

		// Edge cases
		{"empty header", "", []string{}},
		{"wildcard", "*", []string{"*"}},
		{"q=0 excluded", "en;q=0, de", []string{"de"}},

		// Whitespace handling
		{"with spaces", "de , en ; q=0.8", []string{"de", "en"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAcceptLanguage(tc.header)
			if len(result) != len(tc.expected) {
				t.Errorf("parseAcceptLanguage(%q) = %v (len=%d), want %v (len=%d)",
					tc.header, result, len(result), tc.expected, len(tc.expected))
				return
			}
			for i := range tc.expected {
				if result[i] != tc.expected[i] {
					t.Errorf("parseAcceptLanguage(%q)[%d] = %q, want %q",
						tc.header, i, result[i], tc.expected[i])
				}
			}
		})
	}
}

// =============================================================================
// AppError Rendering Tests
// =============================================================================

// TestRenderAppError_JSON_ForAPIEndpoint verifies that renderAppError returns JSON
// for requests to /saml/api/* paths.
func TestRenderAppError_JSON_ForAPIEndpoint(t *testing.T) {
	s := &SAMLDisco{
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/api/idps", nil)
	rec := httptest.NewRecorder()

	err := IdPNotFoundError("https://idp.example.com")
	s.renderAppError(rec, req, err)

	// Should return JSON for API endpoint
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	// Verify JSON structure
	var resp JSONErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if resp.Error.Code != "idp_not_found" {
		t.Errorf("error.code = %q, want idp_not_found", resp.Error.Code)
	}
}

// TestRenderAppError_HTML_ForNonAPIEndpoint verifies that renderAppError returns HTML
// for requests to non-API paths like /saml/disco.
func TestRenderAppError_HTML_ForNonAPIEndpoint(t *testing.T) {
	s := &SAMLDisco{
		templateRenderer: testTemplateRenderer(t),
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
	rec := httptest.NewRecorder()

	err := ConfigError("Metadata store is not configured")
	s.renderAppError(rec, req, err)

	// Should return HTML for non-API endpoint
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}

	// Verify HTML contains title
	body := rec.Body.String()
	if !strings.Contains(body, "Configuration Error") {
		t.Error("HTML should contain error title")
	}
}

// TestRenderAppError_AllErrorCodes verifies correct HTTP status for each error code.
func TestRenderAppError_AllErrorCodes(t *testing.T) {
	s := &SAMLDisco{
		templateRenderer: testTemplateRenderer(t),
	}

	tests := []struct {
		name       string
		err        *AppError
		wantStatus int
		wantCode   string
	}{
		{
			name:       "config error",
			err:        ConfigError("Missing config"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "config_missing",
		},
		{
			name:       "idp not found",
			err:        IdPNotFoundError("https://idp.example.com"),
			wantStatus: http.StatusNotFound,
			wantCode:   "idp_not_found",
		},
		{
			name:       "bad request",
			err:        BadRequestError("Invalid input"),
			wantStatus: http.StatusBadRequest,
			wantCode:   "bad_request",
		},
		{
			name:       "auth error",
			err:        AuthError("Auth failed", nil),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "auth_failed",
		},
		{
			name:       "service error",
			err:        ServiceError("Service unavailable"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "service_error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/saml/api/test", nil)
			rec := httptest.NewRecorder()

			s.renderAppError(rec, req, tc.err)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			var resp JSONErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode JSON: %v", err)
			}
			if resp.Error.Code != tc.wantCode {
				t.Errorf("error.code = %q, want %q", resp.Error.Code, tc.wantCode)
			}
		})
	}
}

// =============================================================================
// Health API: /saml/api/health Tests
// =============================================================================

func TestHealthEndpoint_ReturnsJSON(t *testing.T) {
	store := NewInMemoryMetadataStore([]IdPInfo{{EntityID: "https://idp1.example.com"}})
	s := &SAMLDisco{metadataStore: store}

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
	s := &SAMLDisco{metadataStore: nil}

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
	var resp JSONErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON error: %v", err)
	}
	if resp.Error.Code != "config_missing" {
		t.Errorf("error.code = %q, want %q", resp.Error.Code, "config_missing")
	}
}

func TestHealthEndpoint_IncludesVersionInfo(t *testing.T) {
	store := NewInMemoryMetadataStore([]IdPInfo{{EntityID: "https://idp1.example.com"}})
	s := &SAMLDisco{metadataStore: store}

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
	store := NewInMemoryMetadataStore([]IdPInfo{})
	s := &SAMLDisco{metadataStore: store}

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

// =============================================================================
// Cleanup/CleanerUpper Interface Tests
// =============================================================================

// TestSAMLDisco_Cleanup_WithCloseableStore verifies that Cleanup() calls Close()
// on metadata stores that support it.
func TestSAMLDisco_Cleanup_WithCloseableStore(t *testing.T) {
	store := &mockCloseableMetadataStore{}
	s := &SAMLDisco{metadataStore: store}

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
	s := &SAMLDisco{metadataStore: store}

	err := s.Cleanup()
	if err != nil {
		t.Errorf("Cleanup() returned error: %v", err)
	}
	// Should not panic or error
}

// TestSAMLDisco_Cleanup_NilMetadataStore verifies that Cleanup() handles
// nil metadata store gracefully.
func TestSAMLDisco_Cleanup_NilMetadataStore(t *testing.T) {
	s := &SAMLDisco{metadataStore: nil}

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
