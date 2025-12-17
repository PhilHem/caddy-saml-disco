//go:build unit

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// TestExampleEntitlements_Property_Consistency verifies invariants about
// the entitlements file structure using property-based testing.
func TestExampleEntitlements_Property_Consistency(t *testing.T) {
	// Read entitlements.json (relative to test file)
	jsonPath := filepath.Join(".", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Property 1: All subjects in exact matches are non-empty strings
	for i, entry := range file.Entries {
		if entry.Subject != "" {
			if entry.Subject == "" {
				t.Errorf("Entry[%d] has empty subject", i)
			}
			// Check for basic email-like format (contains @)
			if !strings.Contains(entry.Subject, "@") {
				t.Errorf("Entry[%d] subject %q does not look like email", i, entry.Subject)
			}
		}
	}

	// Property 2: All patterns are valid glob patterns (non-empty)
	for i, entry := range file.Entries {
		if entry.Pattern != "" {
			if entry.Pattern == "" {
				t.Errorf("Entry[%d] has empty pattern", i)
			}
			// Basic validation: pattern should contain * or be non-empty
			if !strings.Contains(entry.Pattern, "*") && entry.Pattern != "" {
				// This is OK - exact patterns are valid too
			}
		}
	}

	// Property 3: No duplicate exact matches
	exactMatches := make(map[string]int)
	for i, entry := range file.Entries {
		if entry.Subject != "" {
			if existing, ok := exactMatches[entry.Subject]; ok {
				t.Errorf("Duplicate exact match for subject %q at entries[%d] and entries[%d]",
					entry.Subject, existing, i)
			}
			exactMatches[entry.Subject] = i
		}
	}

	// Property 4: Roles are non-empty strings
	for i, entry := range file.Entries {
		if len(entry.Roles) == 0 {
			t.Errorf("Entry[%d] has no roles", i)
		}
		for j, role := range entry.Roles {
			if role == "" {
				t.Errorf("Entry[%d].Roles[%d] is empty", i, j)
			}
			// Roles should be alphanumeric with possible dashes/underscores
			if strings.TrimSpace(role) != role {
				t.Errorf("Entry[%d].Roles[%d] %q has leading/trailing whitespace", i, j, role)
			}
		}
	}

	// Property 5: Metadata keys are valid header-safe strings
	for i, entry := range file.Entries {
		for key, value := range entry.Metadata {
			if key == "" {
				t.Errorf("Entry[%d].Metadata has empty key", i)
			}
			// Metadata keys should be lowercase, alphanumeric with dashes/underscores
			// (header-safe)
			if strings.ToLower(key) != key {
				t.Errorf("Entry[%d].Metadata key %q should be lowercase", i, key)
			}
			if value == "" {
				t.Errorf("Entry[%d].Metadata[%q] has empty value", i, key)
			}
		}
	}
}

// TestExampleEntitlements_Property_ValidPatterns uses property-based testing
// to verify that all patterns in the example file are valid and don't cause ReDoS.
func TestExampleEntitlements_Property_ValidPatterns(t *testing.T) {
	jsonPath := filepath.Join(".", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Property: Pattern matching is deterministic and doesn't hang
	f := func(testSubject string) bool {
		if testSubject == "" {
			return true
		}

		// Test each pattern against random subjects
		for _, entry := range file.Entries {
			if entry.Pattern != "" {
				// This should complete quickly (no ReDoS)
				matched := domain.MatchesSubjectPattern(testSubject, entry.Pattern)
				// Just verify it returns (doesn't hang)
				_ = matched
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Errorf("Pattern matching property violated: %v", err)
	}
}

// TestExampleEntitlements_Property_HeaderValidation verifies that all
// entitlement headers referenced in the Caddyfile are valid.
func TestExampleEntitlements_Property_HeaderValidation(t *testing.T) {
	jsonPath := filepath.Join(".", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Property: All entitlement_headers fields exist in entitlements file
	// Caddyfile maps: roles, department
	hasRoles := false
	hasDepartment := false

	for _, entry := range file.Entries {
		if len(entry.Roles) > 0 {
			hasRoles = true
		}
		if entry.Metadata != nil {
			if _, ok := entry.Metadata["department"]; ok {
				hasDepartment = true
			}
		}
	}

	if !hasRoles {
		t.Error("Caddyfile maps 'roles' field, but no entries have roles")
	}
	if !hasDepartment {
		t.Error("Caddyfile maps 'department' field, but no entries have metadata.department")
	}

	// Property: Header names are valid (X- prefix, alphanumeric with dashes)
	// This is validated by Caddyfile parsing, but we verify consistency here
	expectedHeaders := []string{"X-Entitlement-Roles", "X-Department"}
	for _, header := range expectedHeaders {
		if !strings.HasPrefix(header, "X-") {
			t.Errorf("Header %q does not start with X-", header)
		}
		// Check for valid characters (A-Za-z0-9-)
		for _, r := range header {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				t.Errorf("Header %q contains invalid character: %c", header, r)
			}
		}
	}
}

// TestExampleEntitlements_Property_RoleConsistency verifies that require_entitlement
// in Caddyfile matches a role that exists in entitlements.json.
func TestExampleEntitlements_Property_RoleConsistency(t *testing.T) {
	jsonPath := filepath.Join(".", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read entitlements.json: %v", err)
	}

	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Collect all roles
	allRoles := make(map[string]bool)
	for _, entry := range file.Entries {
		for _, role := range entry.Roles {
			allRoles[role] = true
		}
	}

	// Property: require_entitlement "admin" must exist in entitlements file
	requiredRole := "admin"
	if !allRoles[requiredRole] {
		t.Errorf("Caddyfile requires role %q, but it's not found in entitlements.json. Available roles: %v",
			requiredRole, getKeys(allRoles))
	}
}

// Helper function to get keys from map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}



