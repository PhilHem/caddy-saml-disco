//go:build unit

package caddy

import (
	"net/http/httptest"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Cycle 7: RED - Test that applyAttributeHeaders includes entitlements when combined

func TestApplyAttributeHeaders_IncludesEntitlements(t *testing.T) {
	// Setup: Create entitlement store with roles
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	err := entitlementStore.Add(domain.Entitlement{
		Subject: "user@example.edu",
		Roles:   []string{"admin", "staff"},
		Metadata: map[string]string{
			"department": "IT",
		},
	})
	if err != nil {
		t.Fatalf("Failed to add entitlement: %v", err)
	}

	// Create SAMLDisco instance with entitlements configured
	s := &SAMLDisco{
		Config: Config{
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
			EntitlementHeaders: []EntitlementHeaderMapping{
				{Field: "roles", HeaderName: "X-Entitlement-Roles"},
				{Field: "department", HeaderName: "X-Department"},
			},
		},
		entitlementStore: entitlementStore,
	}

	// Create session with SAML attributes
	session := &domain.Session{
		Subject: "user@example.edu",
		Attributes: map[string]string{
			"mail": "user@example.edu",
		},
	}

	// Create request
	req := httptest.NewRequest("GET", "/", nil)

	// Apply headers
	s.applyAttributeHeaders(req, session)

	// Assert: Both SAML attribute AND entitlement headers are present
	if req.Header.Get("X-Remote-User") != "user@example.edu" {
		t.Error("SAML attribute header not set")
	}
	if req.Header.Get("X-Entitlement-Roles") != "admin;staff" {
		t.Errorf("Entitlement roles header not set correctly, got: %q", req.Header.Get("X-Entitlement-Roles"))
	}
	if req.Header.Get("X-Department") != "IT" {
		t.Errorf("Entitlement metadata header not set correctly, got: %q", req.Header.Get("X-Department"))
	}
}

func TestApplyAttributeHeaders_WorksWithoutEntitlements(t *testing.T) {
	// Test that SAML attributes still work when no entitlements are configured
	s := &SAMLDisco{
		Config: Config{
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
		},
	}

	session := &domain.Session{
		Subject: "user@example.edu",
		Attributes: map[string]string{
			"mail": "user@example.edu",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	s.applyAttributeHeaders(req, session)

	if req.Header.Get("X-Remote-User") != "user@example.edu" {
		t.Error("SAML attribute header not set")
	}
}

func TestApplyAttributeHeaders_WorksWithoutEntitlementStore(t *testing.T) {
	// Test that it works when entitlement store is nil
	s := &SAMLDisco{
		Config: Config{
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: "X-Remote-User"},
			},
			EntitlementHeaders: []EntitlementHeaderMapping{
				{Field: "roles", HeaderName: "X-Entitlement-Roles"},
			},
		},
		entitlementStore: nil,
	}

	session := &domain.Session{
		Subject: "user@example.edu",
		Attributes: map[string]string{
			"mail": "user@example.edu",
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	s.applyAttributeHeaders(req, session)

	// Should still set SAML attribute header
	if req.Header.Get("X-Remote-User") != "user@example.edu" {
		t.Error("SAML attribute header not set")
	}
	// Should not set entitlement header (no store)
	if req.Header.Get("X-Entitlement-Roles") != "" {
		t.Error("Entitlement header should not be set when store is nil")
	}
}
