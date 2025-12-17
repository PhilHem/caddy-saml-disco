//go:build unit

package caddy

import (
	"strings"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

func TestMapEntitlementsToHeaders(t *testing.T) {
	result := &domain.EntitlementResult{
		Roles:    []string{"admin", "staff"},
		Metadata: map[string]string{"department": "IT", "access_level": "full"},
	}

	mappings := []EntitlementHeaderMapping{
		{Field: "roles", HeaderName: "X-Entitlement-Roles"},
		{Field: "department", HeaderName: "X-Department"},
		{Field: "access_level", HeaderName: "X-Access-Level"},
	}

	headers, err := MapEntitlementsToHeaders(result, mappings)
	if err != nil {
		t.Fatalf("MapEntitlementsToHeaders() error = %v", err)
	}

	if headers["X-Entitlement-Roles"] != "admin;staff" {
		t.Errorf("X-Entitlement-Roles = %q, want admin;staff", headers["X-Entitlement-Roles"])
	}
	if headers["X-Department"] != "IT" {
		t.Errorf("X-Department = %q, want IT", headers["X-Department"])
	}
	if headers["X-Access-Level"] != "full" {
		t.Errorf("X-Access-Level = %q, want full", headers["X-Access-Level"])
	}
}

// Cycle 21: Property-Based Test - No Header Injection
// Property: Entitlement values never contain CR/LF (header injection prevention)
func TestMapEntitlementsToHeaders_Property_NoHeaderInjection(t *testing.T) {
	f := func(role string) bool {
		result := &domain.EntitlementResult{Roles: []string{role}}
		mappings := []EntitlementHeaderMapping{
			{Field: "roles", HeaderName: "X-Entitlement-Roles"},
		}
		headers, err := MapEntitlementsToHeaders(result, mappings)
		if err != nil {
			return false
		}
		for _, v := range headers {
			if strings.ContainsAny(v, "\r\n") {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapEntitlementsToHeaders_SeparatorSanitizesToEmpty_DefaultsToSemicolon(t *testing.T) {
	// Test that separator containing only control characters sanitizes to empty
	// and re-defaults to ";"
	result := &domain.EntitlementResult{
		Roles: []string{"admin", "user", "editor"},
	}

	mappings := []EntitlementHeaderMapping{
		{
			Field:      "roles",
			HeaderName: "X-Entitlement-Roles",
			Separator:  "\r\n", // Control characters that sanitize to empty
		},
	}

	headers, err := MapEntitlementsToHeaders(result, mappings)
	if err != nil {
		t.Fatalf("MapEntitlementsToHeaders() error = %v", err)
	}

	expected := "admin;user;editor"
	if headers["X-Entitlement-Roles"] != expected {
		t.Errorf("X-Entitlement-Roles = %q, want %q", headers["X-Entitlement-Roles"], expected)
	}
}



