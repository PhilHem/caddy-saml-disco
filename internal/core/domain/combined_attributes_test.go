//go:build unit

package domain

import (
	"testing"
)

// Cycle 1: RED - Write failing test for CombineAttributes

func TestCombineAttributes_PreservesSAMLAttributes(t *testing.T) {
	saml := map[string][]string{"mail": {"user@example.edu"}}
	local := &EntitlementResult{Roles: []string{"admin"}}

	combined := CombineAttributes(saml, local)

	if combined.SAMLAttributes["mail"][0] != "user@example.edu" {
		t.Error("SAML attribute lost")
	}
}

func TestCombineAttributes_PreservesLocalRoles(t *testing.T) {
	saml := map[string][]string{"mail": {"user@example.edu"}}
	local := &EntitlementResult{Roles: []string{"admin", "staff"}}

	combined := CombineAttributes(saml, local)

	if len(combined.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(combined.Roles))
	}
	if combined.Roles[0] != "admin" || combined.Roles[1] != "staff" {
		t.Error("Local roles not preserved")
	}
}

func TestCombineAttributes_PreservesLocalMetadata(t *testing.T) {
	saml := map[string][]string{"mail": {"user@example.edu"}}
	local := &EntitlementResult{
		Roles:    []string{"admin"},
		Metadata: map[string]string{"department": "IT", "access_level": "full"},
	}

	combined := CombineAttributes(saml, local)

	if combined.Metadata["department"] != "IT" {
		t.Error("Local metadata not preserved")
	}
	if combined.Metadata["access_level"] != "full" {
		t.Error("Local metadata not preserved")
	}
}



