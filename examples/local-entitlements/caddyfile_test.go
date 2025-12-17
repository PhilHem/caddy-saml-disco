//go:build unit

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
)

// TestExampleCaddyfile_ParsesCorrectly verifies that the example Caddyfile
// parses without errors and contains all expected entitlements directives.
func TestExampleCaddyfile_ParsesCorrectly(t *testing.T) {
	// Read example Caddyfile (relative to test file)
	caddyfilePath := filepath.Join(".", "Caddyfile")
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		t.Fatalf("Failed to read Caddyfile: %v", err)
	}

	// Extract just the saml_disco block for testing
	// (Caddyfile may have other directives we don't need to test)
	lines := strings.Split(string(content), "\n")
	var samlBlock []string
	inSAMLBlock := false
	braceCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "saml_disco {") {
			inSAMLBlock = true
			braceCount = 1
			samlBlock = append(samlBlock, "saml_disco {")
			continue
		}
		if inSAMLBlock {
			samlBlock = append(samlBlock, line)
			// Count braces to find the end of the block
			for _, r := range line {
				if r == '{' {
					braceCount++
				}
				if r == '}' {
					braceCount--
					if braceCount == 0 {
						break
					}
				}
			}
			if braceCount == 0 {
				break
			}
		}
	}

	if len(samlBlock) == 0 {
		t.Fatal("Could not find saml_disco block in Caddyfile")
	}

	input := strings.Join(samlBlock, "\n")

	// Parse using caddyfile.NewTestDispenser
	d := caddyfile.NewTestDispenser(input)
	var s caddyadapter.SAMLDisco
	err = s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	// Verify entitlements directives are parsed correctly
	if s.EntitlementsFile == "" {
		t.Error("EntitlementsFile not set")
	}
	if s.EntitlementsFile != "./entitlements.json" {
		t.Errorf("EntitlementsFile = %q, want ./entitlements.json", s.EntitlementsFile)
	}

	if s.EntitlementsRefreshInterval == "" {
		t.Error("EntitlementsRefreshInterval not set")
	}
	if s.EntitlementsRefreshInterval != "5m" {
		t.Errorf("EntitlementsRefreshInterval = %q, want 5m", s.EntitlementsRefreshInterval)
	}

	if len(s.EntitlementHeaders) == 0 {
		t.Error("EntitlementHeaders not configured")
	}
	if len(s.EntitlementHeaders) < 2 {
		t.Errorf("EntitlementHeaders length = %d, want at least 2", len(s.EntitlementHeaders))
	}

	// Verify header mappings
	foundRoles := false
	foundDepartment := false
	for _, h := range s.EntitlementHeaders {
		if h.Field == "roles" && h.HeaderName == "X-Entitlement-Roles" {
			foundRoles = true
		}
		if h.Field == "department" && h.HeaderName == "X-Department" {
			foundDepartment = true
		}
	}
	if !foundRoles {
		t.Error("roles -> X-Entitlement-Roles mapping not found")
	}
	if !foundDepartment {
		t.Error("department -> X-Department mapping not found")
	}

	if s.RequireEntitlement == "" {
		t.Error("RequireEntitlement not set")
	}
	if s.RequireEntitlement != "admin" {
		t.Errorf("RequireEntitlement = %q, want admin", s.RequireEntitlement)
	}

	if s.EntitlementDenyRedirect == "" {
		t.Error("EntitlementDenyRedirect not set")
	}
	if s.EntitlementDenyRedirect != "/unauthorized" {
		t.Errorf("EntitlementDenyRedirect = %q, want /unauthorized", s.EntitlementDenyRedirect)
	}
}

// TestExampleCaddyfile_ValidConfiguration verifies that the parsed configuration
// passes validation checks.
func TestExampleCaddyfile_ValidConfiguration(t *testing.T) {
	// Read and parse Caddyfile (relative to test file)
	caddyfilePath := filepath.Join(".", "Caddyfile")
	content, err := os.ReadFile(caddyfilePath)
	if err != nil {
		t.Fatalf("Failed to read Caddyfile: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	var samlBlock []string
	inSAMLBlock := false
	braceCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "saml_disco {") {
			inSAMLBlock = true
			braceCount = 1
			samlBlock = append(samlBlock, "saml_disco {")
			continue
		}
		if inSAMLBlock {
			samlBlock = append(samlBlock, line)
			// Count braces to find the end of the block
			for _, r := range line {
				if r == '{' {
					braceCount++
				}
				if r == '}' {
					braceCount--
					if braceCount == 0 {
						break
					}
				}
			}
			if braceCount == 0 {
				break
			}
		}
	}

	input := strings.Join(samlBlock, "\n")
	d := caddyfile.NewTestDispenser(input)
	var s caddyadapter.SAMLDisco
	err = s.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	// Set required fields for validation
	s.Config.EntityID = "https://myapp.example.com/saml"
	s.Config.MetadataFile = "/etc/caddy/saml/idp-metadata.xml"
	s.Config.CertFile = "/etc/caddy/saml/sp-cert.pem"
	s.Config.KeyFile = "/etc/caddy/saml/sp-key.pem"

	// Validate configuration
	err = s.Config.Validate()
	if err != nil {
		t.Errorf("Config.Validate() error = %v", err)
	}
}



