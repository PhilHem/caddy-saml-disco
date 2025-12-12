//go:build unit

package caddysamldisco

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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

// TestServeHTTP_NoSession_RedirectsToDiscovery verifies that requests without
// a session cookie are redirected to the discovery page.
func TestServeHTTP_NoSession_RedirectsToDiscovery(t *testing.T) {
	// Setup: Create SAMLDisco with session store configured
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Create request without session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	next := &mockNextHandler{}

	// Execute
	err := s.ServeHTTP(rec, req, next)

	// Verify
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	want := "/saml/disco?return_to=%2Fprotected"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}

	if next.called {
		t.Error("next handler should NOT be called when no session")
	}
}

// TestServeHTTP_InvalidSession_RedirectsToDiscovery verifies that requests with
// an invalid/expired/tampered session cookie are redirected to the discovery page.
func TestServeHTTP_InvalidSession_RedirectsToDiscovery(t *testing.T) {
	// Setup: Create SAMLDisco with session store configured
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
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
			want := "/saml/disco?return_to=%2Fprotected"
			if location != want {
				t.Errorf("Location = %q, want %q", location, want)
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

// TestServeHTTP_CustomLoginRedirect verifies that when LoginRedirect is configured,
// unauthenticated requests redirect to the custom URL instead of /saml/disco.
func TestServeHTTP_CustomLoginRedirect(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
			LoginRedirect:     "/custom/login",
		},
		sessionStore: store,
	}

	// Request without session cookie
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
	want := "/custom/login?return_to=%2Fprotected"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}
}

// TestServeHTTP_PreservesOriginalURL verifies that the original URL is preserved
// in the redirect so users can be redirected back after login.
func TestServeHTTP_PreservesOriginalURL(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	s := &SAMLDisco{
		Config: Config{
			SessionCookieName: "saml_session",
		},
		sessionStore: store,
	}

	// Request to a protected URL with query params
	req := httptest.NewRequest(http.MethodGet, "/protected/page?foo=bar&baz=qux", nil)
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
	// Should redirect with return_to parameter
	want := "/saml/disco?return_to=%2Fprotected%2Fpage%3Ffoo%3Dbar%26baz%3Dqux"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
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
