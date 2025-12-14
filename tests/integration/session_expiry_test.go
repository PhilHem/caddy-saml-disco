//go:build integration

// Package integration contains integration tests for caddy-saml-disco.
// These tests are in a separate package but use the caddysamldisco package
// name to access internal fields for testing.
package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddysamldisco "github.com/philiph/caddy-saml-disco"
)

// mockNextHandler tracks if request passed through middleware.
type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*mockNextHandler)(nil)

// mockMetadataStore provides IdP info for redirects.
type mockMetadataStore struct {
	idps []caddysamldisco.IdPInfo
}

func (m *mockMetadataStore) GetIdP(entityID string) (*caddysamldisco.IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, caddysamldisco.ErrIdPNotFound
}

func (m *mockMetadataStore) ListIdPs(filter string) ([]caddysamldisco.IdPInfo, error) {
	return m.idps, nil
}

func (m *mockMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStore) Health() caddysamldisco.MetadataHealth {
	return caddysamldisco.MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// TestSessionExpiry_ValidThenExpired_RedirectsToIdP verifies that a valid session
// passes through to the next handler, but after expiration redirects to the IdP.
//
// Note: Uses 2-second duration because JWT exp claim uses Unix timestamps with
// second precision. Sub-second durations may expire immediately due to rounding.
func TestSessionExpiry_ValidThenExpired_RedirectsToIdP(t *testing.T) {
	// 1. Setup - Load credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}

	// 2. Create store with 2 second duration
	store := caddysamldisco.NewCookieSessionStore(key, 2*time.Second)

	// 3. Create valid session token
	session := &caddysamldisco.Session{
		Subject:     "testuser",
		IdPEntityID: "https://idp.example.com",
	}
	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 4. Create SAMLDisco middleware
	samlService := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)
	metadataStore := &mockMetadataStore{
		idps: []caddysamldisco.IdPInfo{{
			EntityID:   "https://idp.example.com",
			SSOURL:     "https://idp.example.com/sso",
			SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		}},
	}

	s := caddysamldisco.NewSAMLDiscoForTest(
		caddysamldisco.Config{
			EntityID:          "https://sp.example.com",
			SessionCookieName: "saml_session",
		},
		store,
		samlService,
		metadataStore,
	)

	// 5. First request - should pass (valid session)
	req1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req1.Host = "sp.example.com"
	req1.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
	rec1 := httptest.NewRecorder()
	next1 := &mockNextHandler{}

	err = s.ServeHTTP(rec1, req1, next1)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if !next1.called {
		t.Error("valid session: next handler should be called")
	}
	if rec1.Code != http.StatusOK {
		t.Errorf("valid session: got %d, want %d", rec1.Code, http.StatusOK)
	}

	// 6. Wait for token to expire (2 seconds + buffer)
	time.Sleep(3 * time.Second)

	// 7. Second request - should redirect (expired)
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.Host = "sp.example.com"
	req2.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
	rec2 := httptest.NewRecorder()
	next2 := &mockNextHandler{}

	err = s.ServeHTTP(rec2, req2, next2)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if next2.called {
		t.Error("expired session: next handler should NOT be called")
	}
	if rec2.Code != http.StatusFound {
		t.Errorf("expired session: got %d, want %d", rec2.Code, http.StatusFound)
	}

	location := rec2.Header().Get("Location")
	if !strings.HasPrefix(location, "https://idp.example.com/sso") {
		t.Errorf("expired session: redirect to %q, want IdP SSO URL prefix", location)
	}
}
