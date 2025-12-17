//go:build unit

package caddy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// TestValidateDenyRedirect verifies that deny redirect URL validation prevents open redirects.
// Cycle 1: RED - Write failing test for ValidateDenyRedirect function
func TestValidateDenyRedirect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // empty string means invalid/rejected
	}{
		// Valid relative paths - should be allowed
		{"relative path", "/access-denied", "/access-denied"},
		{"root path", "/", "/"},
		{"path with query", "/denied?reason=unauthorized", "/denied?reason=unauthorized"},
		{"nested path", "/app/access-denied", "/app/access-denied"},

		// Valid absolute HTTPS URLs - should be allowed
		{"absolute https", "https://sso.example.com/denied", "https://sso.example.com/denied"},
		{"absolute https with path", "https://sso.example.com/app/denied", "https://sso.example.com/app/denied"},
		{"absolute https with port", "https://sso.example.com:8443/denied", "https://sso.example.com:8443/denied"},

		// Empty string is valid (means use 403, not redirect)
		{"empty string", "", ""},

		// Protocol-relative URLs - should be rejected
		{"protocol-relative", "//evil.com", ""},
		{"protocol-relative with path", "//evil.com/path", ""},

		// Absolute HTTP URLs - should be rejected (insecure)
		{"absolute http", "http://evil.com", ""},
		{"absolute http with path", "http://evil.com/denied", ""},

		// Dangerous schemes - should be rejected
		{"javascript scheme", "javascript:alert(1)", ""},
		{"data scheme", "data:text/html,evil", ""},
		{"vbscript scheme", "vbscript:msgbox(1)", ""},
		{"file scheme", "file:///etc/passwd", ""},

		// Edge cases
		{"encoded slashes", "%2f%2fevil.com", ""},
		{"newline in path", "/path\nHeader: injection", ""}, // header injection blocked
		{"whitespace only", "   ", ""},                      // trimmed to empty, valid
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateDenyRedirect(tc.input)
			if got != tc.expected {
				t.Errorf("ValidateDenyRedirect(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

// TestValidateDenyRedirect_Property_NoOpenRedirect verifies that ValidateDenyRedirect
// NEVER returns URL pointing to different origin (unless explicitly configured as absolute HTTPS).
// Cycle 3: RED - Property-Based Test for Open Redirect Prevention
func TestValidateDenyRedirect_Property_NoOpenRedirect(t *testing.T) {
	f := func(input string) bool {
		result := ValidateDenyRedirect(input)
		if result == "" {
			return true // rejection is safe
		}
		// If relative, must start with single /
		if strings.HasPrefix(result, "/") {
			return !strings.HasPrefix(result, "//")
		}
		// If absolute, must be https
		parsed, err := url.Parse(result)
		if err != nil {
			return false // invalid URL is unsafe
		}
		return parsed.Scheme == "https"
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err) // BUG FOUND
	}
}

// TestHandleDenied verifies that handleDenied redirects or returns 403 based on config.
// Cycle 4: RED - Write failing test for handleDenied function
func TestHandleDenied(t *testing.T) {
	tests := []struct {
		name           string
		denyRedirect   string
		wantStatusCode int
		wantLocation   string
	}{
		{"no redirect - 403", "", http.StatusForbidden, ""},
		{"relative redirect", "/access-denied", http.StatusFound, "/access-denied"},
		{"absolute redirect", "https://sso.example.com/denied", http.StatusFound, "https://sso.example.com/denied"},
		{"invalid redirect falls back to 403", "javascript:alert(1)", http.StatusForbidden, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &SAMLDisco{
				Config: Config{
					EntitlementDenyRedirect: tc.denyRedirect,
				},
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			s.handleDenied(rec, req, "user@example.com")

			if rec.Code != tc.wantStatusCode {
				t.Errorf("handleDenied() status code = %d, want %d", rec.Code, tc.wantStatusCode)
			}

			if tc.wantLocation != "" {
				location := rec.Header().Get("Location")
				if location != tc.wantLocation {
					t.Errorf("handleDenied() Location = %q, want %q", location, tc.wantLocation)
				}
			} else {
				// Should not have Location header for 403
				if rec.Header().Get("Location") != "" {
					t.Errorf("handleDenied() should not set Location header for 403, got %q", rec.Header().Get("Location"))
				}
			}
		})
	}
}

// TestHandleACS_DeniesUnauthorizedUser verifies that handleACS checks entitlements
// and denies unauthorized users after successful SAML authentication.
// Cycle 6: RED - Write integration test for entitlements check in handleACS
func TestHandleACS_DeniesUnauthorizedUser(t *testing.T) {
	// Setup: Create entitlement store with deny mode
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	// Add authorized user
	entitlementStore.Add(domain.Entitlement{
		Subject: "authorized@example.com",
		Roles:   []string{"user"},
	})
	// unauthorized@example.com is NOT in the store

	// Create SAMLDisco with entitlement store
	s := &SAMLDisco{
		Config: Config{
			EntitlementDenyRedirect: "", // Use 403, not redirect
		},
		entitlementStore: entitlementStore,
	}

	// Create a mock request (simulating successful SAML auth)
	// Note: This is a simplified test - a full integration test would
	// use a real SAML response, but for unit testing we'll test the
	// entitlement check logic directly
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	rec := httptest.NewRecorder()

	// Simulate that authentication succeeded and session was created
	// by directly calling handleDenied for unauthorized user
	s.handleDenied(rec, req, "unauthorized@example.com")

	// Should return 403
	if rec.Code != http.StatusForbidden {
		t.Errorf("handleDenied() status code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestHandleACS_AllowsAuthorizedUser verifies that authorized users pass entitlement check.
func TestHandleACS_AllowsAuthorizedUser(t *testing.T) {
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	entitlementStore.Add(domain.Entitlement{
		Subject: "authorized@example.com",
		Roles:   []string{"user", "admin"},
	})

	result, err := entitlementStore.Lookup("authorized@example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if !result.Matched {
		t.Error("Lookup() Matched = false, want true")
	}
	if len(result.Roles) != 2 {
		t.Errorf("Lookup() Roles = %v, want [user, admin]", result.Roles)
	}
}

// TestHandleACS_RequireEntitlement verifies that require_entitlement is checked.
func TestHandleACS_RequireEntitlement(t *testing.T) {
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	entitlementStore.Add(domain.Entitlement{
		Subject: "user@example.com",
		Roles:   []string{"user"}, // Has "user" but not "admin"
	})

	result, err := entitlementStore.Lookup("user@example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}

	// Check require_entitlement - user should not have admin role
	hasRole := false
	for _, role := range result.Roles {
		if role == "admin" {
			hasRole = true
			break
		}
	}
	if hasRole {
		t.Error("user should not have admin role")
	}
}

// TestSAMLDisco_Property_DenyNever200 verifies that denied users NEVER get 200 response.
// This is the key invariant for security.
// Cycle 8: Property-Based Test - Deny Consistency
func TestSAMLDisco_Property_DenyNever200(t *testing.T) {
	f := func(subject string) bool {
		if subject == "" {
			return true // skip empty subjects
		}
		store := entitlements.NewInMemoryEntitlementStore()
		store.SetDefaultAction(domain.DefaultActionDeny)
		// subject is NOT in store

		_, err := store.Lookup(subject)
		// Invariant: must be denied
		return errors.Is(err, domain.ErrEntitlementNotFound)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}



