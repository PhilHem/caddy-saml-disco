//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddysamldisco "github.com/philiph/caddy-saml-disco"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// TestLocalEntitlementsExample_EndToEndFlow tests the example entitlements.json
// file end-to-end, verifying that the configuration works as expected.
func TestLocalEntitlementsExample_EndToEndFlow(t *testing.T) {
	// Load example entitlements.json
	jsonPath := filepath.Join("..", "..", "examples", "local-entitlements", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read example entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal entitlements.json: %v", err)
	}

	// Create file-based entitlement store (simulating the example)
	// For testing, we'll use in-memory store with the same data
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	if file.DefaultAction == "deny" {
		entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	} else {
		entitlementStore.SetDefaultAction(domain.DefaultActionAllow)
	}

	// Add all entries from example file
	for _, entry := range file.Entries {
		err := entitlementStore.Add(entry)
		if err != nil {
			t.Fatalf("Failed to add entitlement: %v", err)
		}
	}

	// Load SP credentials for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Test Case 1: Admin user can access (has admin role)
	t.Run("AdminUserAccess", func(t *testing.T) {
		session := &caddysamldisco.Session{
			Subject:     "admin@example.edu",
			Attributes:  map[string]string{"mail": "admin@example.edu"},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Roles"},
					{Field: "department", HeaderName: "X-Department"},
				},
				RequireEntitlement: "admin",
			},
		}
		disco.SetSessionStore(sessionStore)
		disco.SetEntitlementStore(entitlementStore)

		captured := &capturedHeaders{}
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
		rec := httptest.NewRecorder()

		err = disco.ServeHTTP(rec, req, captured)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		// Admin should have access
		if !captured.called {
			t.Error("Admin user should have access, but handler was not called")
		}

		// Verify headers
		gotRoles := captured.headers.Get("X-Entitlement-Roles")
		if gotRoles != "admin;staff" {
			t.Errorf("X-Entitlement-Roles = %q, want admin;staff", gotRoles)
		}
		gotDept := captured.headers.Get("X-Department")
		if gotDept != "IT" {
			t.Errorf("X-Department = %q, want IT", gotDept)
		}
	})

	// Test Case 2: Regular user (pattern match) gets user role
	// Note: require_entitlement is only checked during ACS, not on regular requests.
	// For regular requests, the application should check X-Entitlement-Roles header.
	t.Run("RegularUserGetsUserRole", func(t *testing.T) {
		session := &caddysamldisco.Session{
			Subject:     "user@example.edu",
			Attributes:  map[string]string{"mail": "user@example.edu"},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				},
			},
		}
		disco.SetSessionStore(sessionStore)
		disco.SetEntitlementStore(entitlementStore)

		captured := &capturedHeaders{}
		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		req.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
		rec := httptest.NewRecorder()

		err = disco.ServeHTTP(rec, req, captured)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		// Verify user gets 'user' role from pattern match
		gotRoles := captured.headers.Get("X-Entitlement-Roles")
		if gotRoles != "user" {
			t.Errorf("X-Entitlement-Roles = %q, want user (pattern match)", gotRoles)
		}
	})

	// Test Case 3: Pattern matching works (staff@*)
	t.Run("PatternMatching", func(t *testing.T) {
		session := &caddysamldisco.Session{
			Subject:     "staff@anywhere.com",
			Attributes:  map[string]string{"mail": "staff@anywhere.com"},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				},
				// Don't require admin for this test
			},
		}
		disco.SetSessionStore(sessionStore)
		disco.SetEntitlementStore(entitlementStore)

		captured := &capturedHeaders{}
		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		req.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
		rec := httptest.NewRecorder()

		err = disco.ServeHTTP(rec, req, captured)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		// Verify pattern match worked
		gotRoles := captured.headers.Get("X-Entitlement-Roles")
		if gotRoles != "staff" {
			t.Errorf("X-Entitlement-Roles = %q, want staff (pattern match)", gotRoles)
		}
	})

	// Test Case 4: External user - no entitlements (allowlist mode)
	// Note: Entitlement checking happens during ACS, not on regular requests.
	// For regular requests, entitlements are just injected as headers (or not).
	t.Run("ExternalUserNoEntitlements", func(t *testing.T) {
		session := &caddysamldisco.Session{
			Subject:     "external@other.com",
			Attributes:  map[string]string{"mail": "external@other.com"},
			IdPEntityID: "https://idp.example.com",
			IssuedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(8 * time.Hour),
		}

		token, err := sessionStore.Create(session)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		disco := &caddysamldisco.SAMLDisco{
			Config: caddysamldisco.Config{
				SessionCookieName: "saml_session",
				EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				},
			},
		}
		disco.SetSessionStore(sessionStore)
		disco.SetEntitlementStore(entitlementStore)

		captured := &capturedHeaders{}
		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		req.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
		rec := httptest.NewRecorder()

		err = disco.ServeHTTP(rec, req, captured)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}

		// External user should not have entitlement headers (not in file)
		gotRoles := captured.headers.Get("X-Entitlement-Roles")
		if gotRoles != "" {
			t.Errorf("X-Entitlement-Roles = %q, want empty (user not in entitlements file)", gotRoles)
		}
	})
}

// TestLocalEntitlementsExample_HeaderInjection verifies that entitlement headers
// are correctly injected as specified in the example Caddyfile.
func TestLocalEntitlementsExample_HeaderInjection(t *testing.T) {
	// Load example entitlements.json
	jsonPath := filepath.Join("..", "..", "examples", "local-entitlements", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read example entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal entitlements.json: %v", err)
	}

	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	for _, entry := range file.Entries {
		entitlementStore.Add(entry)
	}

	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Test manager@example.edu (has department metadata)
	session := &caddysamldisco.Session{
		Subject:     "manager@example.edu",
		Attributes:  map[string]string{"mail": "manager@example.edu"},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Use example Caddyfile configuration
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
				{Field: "roles", HeaderName: "X-Entitlement-Roles", Separator: ";"},
				{Field: "department", HeaderName: "X-Department"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)
	disco.SetEntitlementStore(entitlementStore)

	captured := &capturedHeaders{}
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	req.AddCookie(&http.Cookie{Name: "saml_session", Value: token})
	rec := httptest.NewRecorder()

	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify headers match example configuration
	gotRoles := captured.headers.Get("X-Entitlement-Roles")
	if gotRoles != "manager;staff" {
		t.Errorf("X-Entitlement-Roles = %q, want manager;staff", gotRoles)
	}

	gotDept := captured.headers.Get("X-Department")
	if gotDept != "Operations" {
		t.Errorf("X-Department = %q, want Operations", gotDept)
	}
}

// capturedHeaders records headers seen by downstream handler
type capturedHeaders struct {
	headers http.Header
	called  bool
}

func (c *capturedHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	c.headers = r.Header.Clone()
	c.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*capturedHeaders)(nil)
