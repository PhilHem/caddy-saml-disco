//go:build unit

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
)

// TestExampleEntitlementsJSON_ValidSchema verifies that the example entitlements.json
// has valid structure and can be unmarshaled correctly.
func TestExampleEntitlementsJSON_ValidSchema(t *testing.T) {
	// Read entitlements.json (relative to test file)
	jsonPath := filepath.Join(".", "entitlements.json")
	content, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("Failed to read entitlements.json: %v", err)
	}

	// Unmarshal into EntitlementsFile struct
	var file entitlements.EntitlementsFile
	err = json.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify structure matches expected format
	if file.DefaultAction == "" {
		t.Error("default_action not set")
	}
	if file.DefaultAction != "deny" && file.DefaultAction != "allow" {
		t.Errorf("default_action = %q, want 'deny' or 'allow'", file.DefaultAction)
	}

	if len(file.Entries) == 0 {
		t.Error("entries array is empty")
	}

	// Validate each entry
	for i, entry := range file.Entries {
		err := entry.Validate()
		if err != nil {
			t.Errorf("Entry[%d] validation failed: %v", i, err)
		}

		// Verify no invalid patterns or subjects
		if entry.Subject != "" && entry.Pattern != "" {
			t.Errorf("Entry[%d] has both subject and pattern", i)
		}
		if entry.Subject == "" && entry.Pattern == "" {
			t.Errorf("Entry[%d] has neither subject nor pattern", i)
		}

		// Verify roles are non-empty strings
		for j, role := range entry.Roles {
			if role == "" {
				t.Errorf("Entry[%d].Roles[%d] is empty", i, j)
			}
		}

		// Verify metadata keys are valid (non-empty strings)
		for key, value := range entry.Metadata {
			if key == "" {
				t.Errorf("Entry[%d].Metadata has empty key", i)
			}
			if value == "" {
				t.Errorf("Entry[%d].Metadata[%q] has empty value", i, key)
			}
		}
	}
}

// TestExampleEntitlementsJSON_Consistency verifies consistency between
// Caddyfile configuration and entitlements.json.
func TestExampleEntitlementsJSON_Consistency(t *testing.T) {
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

	// Collect all roles from entitlements file
	allRoles := make(map[string]bool)
	for _, entry := range file.Entries {
		for _, role := range entry.Roles {
			allRoles[role] = true
		}
	}

	// Verify that 'admin' role exists (required by Caddyfile require_entitlement)
	if !allRoles["admin"] {
		t.Error("'admin' role not found in entitlements.json, but Caddyfile requires it")
	}

	// Verify no duplicate exact matches
	exactMatches := make(map[string]bool)
	for _, entry := range file.Entries {
		if entry.Subject != "" {
			if exactMatches[entry.Subject] {
				t.Errorf("Duplicate exact match for subject: %q", entry.Subject)
			}
			exactMatches[entry.Subject] = true
		}
	}
}

// TestExampleEntitlementsYAML_ValidSchema verifies that the example entitlements.yaml
// has valid structure (if YAML support is available).
func TestExampleEntitlementsYAML_ValidSchema(t *testing.T) {
	// Read entitlements.yaml (relative to test file)
	yamlPath := filepath.Join(".", "entitlements.yaml")
	content, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Skipf("YAML file not found or unreadable: %v", err)
	}

	// Parse YAML (using the same EntitlementsFile struct)
	var file entitlements.EntitlementsFile
	err = yaml.Unmarshal(content, &file)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML: %v", err)
	}

	// Verify structure (same checks as JSON)
	if file.DefaultAction == "" {
		t.Error("default_action not set")
	}

	if len(file.Entries) == 0 {
		t.Error("entries array is empty")
	}

	// Validate each entry
	for i, entry := range file.Entries {
		err := entry.Validate()
		if err != nil {
			t.Errorf("Entry[%d] validation failed: %v", i, err)
		}
	}
}



