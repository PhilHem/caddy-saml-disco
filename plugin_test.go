//go:build unit

package caddysamldisco

import (
	"context"
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
	if !strings.Contains(body, "Metadata store not configured") {
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
	if !strings.Contains(body, "SAML service not configured") {
		t.Errorf("error message should mention SAML service, got: %q", body)
	}
}
