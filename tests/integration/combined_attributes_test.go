//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Cycle 10: Integration Test - End-to-End Combined Headers
// Tests that SAML attributes and local entitlements are combined and both reach downstream handlers
func TestCombinedAttributes_ReachDownstreamHandler(t *testing.T) {
	// Load SP credentials for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session store
	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create entitlement store with test data
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionAllow) // Allow mode for testing
	err = entitlementStore.Add(domain.Entitlement{
		Subject: "user@example.com",
		Roles:   []string{"admin", "staff"},
		Metadata: map[string]string{
			"department": "IT",
		},
	})
	if err != nil {
		t.Fatalf("add entitlement: %v", err)
	}

	// Create session with SAML attributes
	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"mail":                   "user@example.com",
			"eduPersonPrincipalName": "user@example.com",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	// Create session token
	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Create SAMLDisco with both attribute_headers and entitlement_headers configured
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
			EntitlementHeaders: []caddyadapter.EntitlementHeaderMapping{
				{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				{Field: "department", HeaderName: "X-Department"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)
	disco.SetEntitlementStore(entitlementStore)

	// Create downstream handler that captures headers
	captured := &capturedHeaders{}

	// Make request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	// Call ServeHTTP directly
	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify downstream handler was called
	if !captured.called {
		t.Fatal("downstream handler was not called")
	}

	// Verify SAML attribute header was set
	gotSAMLAttr := captured.headers.Get("X-Remote-User")
	if gotSAMLAttr != "user@example.com" {
		t.Errorf("X-Remote-User header = %q, want %q", gotSAMLAttr, "user@example.com")
	}

	// Verify entitlement roles header was set
	gotRoles := captured.headers.Get("X-Entitlement-Roles")
	if gotRoles != "admin;staff" {
		t.Errorf("X-Entitlement-Roles header = %q, want %q", gotRoles, "admin;staff")
	}

	// Verify entitlement metadata header was set
	gotDept := captured.headers.Get("X-Department")
	if gotDept != "IT" {
		t.Errorf("X-Department header = %q, want %q", gotDept, "IT")
	}
}

// TestCombinedAttributes_WorksWithoutEntitlements verifies backward compatibility:
// SAML attributes still work when entitlements are not configured
func TestCombinedAttributes_WorksWithoutEntitlements(t *testing.T) {
	// Load SP credentials for session store
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}

	// Create session store
	sessionStore := caddysamldisco.NewCookieSessionStore(key, 8*time.Hour)

	// Create session with SAML attributes
	session := &caddysamldisco.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"mail": "user@example.com",
		},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	// Create session token
	token, err := sessionStore.Create(session)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Create SAMLDisco with only attribute_headers (no entitlements)
	disco := &caddysamldisco.SAMLDisco{
		Config: caddysamldisco.Config{
			SessionCookieName: "saml_session",
			AttributeHeaders: []caddysamldisco.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
		},
	}
	disco.SetSessionStore(sessionStore)

	// Create downstream handler that captures headers
	captured := &capturedHeaders{}

	// Make request with session cookie
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "saml_session",
		Value: token,
	})
	rec := httptest.NewRecorder()

	// Call ServeHTTP directly
	err = disco.ServeHTTP(rec, req, captured)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Verify SAML attribute header was set
	gotSAMLAttr := captured.headers.Get("X-Remote-User")
	if gotSAMLAttr != "user@example.com" {
		t.Errorf("X-Remote-User header = %q, want %q", gotSAMLAttr, "user@example.com")
	}

	// Verify entitlement headers are NOT set (entitlements not configured)
	if captured.headers.Get("X-Entitlement-Roles") != "" {
		t.Error("X-Entitlement-Roles should not be set when entitlements are not configured")
	}
}






