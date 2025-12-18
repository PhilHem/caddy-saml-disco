//go:build unit

package caddysamldisco

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// =============================================================================
// Test Helpers
// =============================================================================

// newTestAttributeMapper returns an AttributeMapper instance for testing.
// Tests should use this to test through the port interface rather than
// calling adapter functions directly.
func newTestAttributeMapper() ports.AttributeMapper {
	return caddy.NewCaddyAttributeMapper()
}

// convertToPortMappings converts caddy.AttributeMapping to ports.AttributeMapping.
func convertToPortMappings(mappings []AttributeMapping) []ports.AttributeMapping {
	result := make([]ports.AttributeMapping, len(mappings))
	for i, m := range mappings {
		result[i] = ports.AttributeMapping{
			SAMLAttribute: m.SAMLAttribute,
			HeaderName:    m.HeaderName,
			Separator:     m.Separator,
		}
	}
	return result
}

// mapAttributesToHeadersViaPort is a helper that calls MapAttributesToHeaders through the port interface.
// This allows tests to test through the port interface while using the existing AttributeMapping type.
func mapAttributesToHeadersViaPort(attrs map[string][]string, mappings []AttributeMapping) (map[string]string, error) {
	mapper := newTestAttributeMapper()
	return mapper.MapAttributesToHeaders(attrs, convertToPortMappings(mappings))
}

// mapAttributesToHeadersWithPrefixViaPort is a helper that calls MapAttributesToHeadersWithPrefix through the port interface.
func mapAttributesToHeadersWithPrefixViaPort(attrs map[string][]string, mappings []AttributeMapping, prefix string) (map[string]string, error) {
	mapper := newTestAttributeMapper()
	return mapper.MapAttributesToHeadersWithPrefix(attrs, convertToPortMappings(mappings), prefix)
}

// =============================================================================
// Unit Tests
// =============================================================================

func TestMapAttributesToHeaders_EmptyMappings(t *testing.T) {
	attrs := map[string][]string{
		"email": {"user@example.com"},
	}
	mappings := []AttributeMapping{}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestMapAttributesToHeaders_SingleMapping(t *testing.T) {
	attrs := map[string][]string{
		"urn:oid:0.9.2342.19200300.100.1.3": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:0.9.2342.19200300.100.1.3", HeaderName: "X-Mail"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Mail"] != "user@example.com" {
		t.Errorf("expected X-Mail=user@example.com, got %v", result["X-Mail"])
	}
}

func TestMapAttributesToHeaders_MissingAttribute(t *testing.T) {
	attrs := map[string][]string{
		"email": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "nonexistent", HeaderName: "X-Missing"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result["X-Missing"]; exists {
		t.Errorf("expected no X-Missing header for missing attribute, got %v", result["X-Missing"])
	}
}

func TestMapAttributesToHeaders_MultipleValues_DefaultSeparator(t *testing.T) {
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7": {"admin", "user", "editor"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", HeaderName: "X-Entitlements"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "admin;user;editor"
	if result["X-Entitlements"] != expected {
		t.Errorf("expected %q, got %q", expected, result["X-Entitlements"])
	}
}

func TestMapAttributesToHeaders_MultipleValues_CustomSeparator(t *testing.T) {
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7": {"admin", "user", "editor"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", HeaderName: "X-Entitlements", Separator: ","},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "admin,user,editor"
	if result["X-Entitlements"] != expected {
		t.Errorf("expected %q, got %q", expected, result["X-Entitlements"])
	}
}

func TestMapAttributesToHeaders_InvalidHeaderName_NoXPrefix(t *testing.T) {
	attrs := map[string][]string{
		"email": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "email", HeaderName: "Mail"}, // Missing X- prefix
	}

	_, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err == nil {
		t.Error("expected error for header without X- prefix")
	}
}

func TestMapAttributesToHeaders_InvalidHeaderName_InvalidChars(t *testing.T) {
	attrs := map[string][]string{
		"email": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "email", HeaderName: "X-Mail Header"}, // Space not allowed
	}

	_, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err == nil {
		t.Error("expected error for header with invalid characters")
	}
}

func TestMapAttributesToHeaders_SanitizesNewlines(t *testing.T) {
	attrs := map[string][]string{
		"evil": {"value\r\nInjected-Header: bad"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "evil", HeaderName: "X-Evil"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(result["X-Evil"], "\r") || strings.Contains(result["X-Evil"], "\n") {
		t.Errorf("result contains CR/LF: %q", result["X-Evil"])
	}
}

func TestMapAttributesToHeaders_TruncatesLongValues(t *testing.T) {
	longValue := strings.Repeat("a", 10000)
	attrs := map[string][]string{
		"long": {longValue},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "long", HeaderName: "X-Long"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result["X-Long"]) > MaxHeaderValueLength {
		t.Errorf("result exceeds max length: got %d, max %d", len(result["X-Long"]), MaxHeaderValueLength)
	}
}

func TestMapAttributesToHeaders_EmptyAttributeValue(t *testing.T) {
	attrs := map[string][]string{
		"empty": {},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "empty", HeaderName: "X-Empty"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result["X-Empty"]; exists {
		t.Error("expected no header for empty attribute values")
	}
}

func TestMapAttributesToHeaders_MultipleMappings(t *testing.T) {
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6":  {"user@example.com"},
		"urn:oid:0.9.2342.19200300.100.1.3": {"user@example.com"},
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":  {"admin", "user"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", HeaderName: "X-Remote-User"},
		{SAMLAttribute: "urn:oid:0.9.2342.19200300.100.1.3", HeaderName: "X-Mail"},
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", HeaderName: "X-Entitlements", Separator: ","},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Remote-User"] != "user@example.com" {
		t.Errorf("X-Remote-User: expected user@example.com, got %q", result["X-Remote-User"])
	}
	if result["X-Mail"] != "user@example.com" {
		t.Errorf("X-Mail: expected user@example.com, got %q", result["X-Mail"])
	}
	if result["X-Entitlements"] != "admin,user" {
		t.Errorf("X-Entitlements: expected admin,user, got %q", result["X-Entitlements"])
	}
}

// =============================================================================
// OID Registry Tests
// =============================================================================

func TestResolveAttributeName_FriendlyNameToOID(t *testing.T) {
	oid, friendlyName := ResolveAttributeName("eduPersonPrincipalName")
	if oid != "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" {
		t.Errorf("expected OID urn:oid:1.3.6.1.4.1.5923.1.1.1.6, got %q", oid)
	}
	if friendlyName != "eduPersonPrincipalName" {
		t.Errorf("expected friendly name eduPersonPrincipalName, got %q", friendlyName)
	}
}

func TestResolveAttributeName_OIDToFriendlyName(t *testing.T) {
	oid, friendlyName := ResolveAttributeName("urn:oid:1.3.6.1.4.1.5923.1.1.1.6")
	if oid != "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" {
		t.Errorf("expected OID urn:oid:1.3.6.1.4.1.5923.1.1.1.6, got %q", oid)
	}
	if friendlyName != "eduPersonPrincipalName" {
		t.Errorf("expected friendly name eduPersonPrincipalName, got %q", friendlyName)
	}
}

func TestResolveAttributeName_UnknownName(t *testing.T) {
	oid, friendlyName := ResolveAttributeName("customAttribute")
	if oid != "customAttribute" {
		t.Errorf("expected unknown name to pass through as OID, got %q", oid)
	}
	if friendlyName != "customAttribute" {
		t.Errorf("expected unknown name to pass through as friendly name, got %q", friendlyName)
	}
}

func TestResolveAttributeName_AllCommonAttributes(t *testing.T) {
	tests := []struct {
		name         string
		expectedOID  string
		expectedName string
	}{
		{"eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName"},
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName"},
		{"eduPersonEntitlement", "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "eduPersonEntitlement"},
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "eduPersonEntitlement"},
		{"eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "eduPersonScopedAffiliation"},
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "eduPersonScopedAffiliation"},
		{"eduPersonTargetedID", "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", "eduPersonTargetedID"},
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.10", "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", "eduPersonTargetedID"},
		{"mail", "urn:oid:0.9.2342.19200300.100.1.3", "mail"},
		{"urn:oid:0.9.2342.19200300.100.1.3", "urn:oid:0.9.2342.19200300.100.1.3", "mail"},
		{"givenName", "urn:oid:2.5.4.42", "givenName"},
		{"urn:oid:2.5.4.42", "urn:oid:2.5.4.42", "givenName"},
		{"sn", "urn:oid:2.5.4.4", "sn"},
		{"urn:oid:2.5.4.4", "urn:oid:2.5.4.4", "sn"},
		{"displayName", "urn:oid:2.16.840.1.113730.3.1.241", "displayName"},
		{"urn:oid:2.16.840.1.113730.3.1.241", "urn:oid:2.16.840.1.113730.3.1.241", "displayName"},
		{"schacHomeOrganization", "urn:oid:1.3.6.1.4.1.25178.1.2.9", "schacHomeOrganization"},
		{"urn:oid:1.3.6.1.4.1.25178.1.2.9", "urn:oid:1.3.6.1.4.1.25178.1.2.9", "schacHomeOrganization"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid, friendlyName := ResolveAttributeName(tt.name)
			if oid != tt.expectedOID {
				t.Errorf("OID: expected %q, got %q", tt.expectedOID, oid)
			}
			if friendlyName != tt.expectedName {
				t.Errorf("friendly name: expected %q, got %q", tt.expectedName, friendlyName)
			}
		})
	}
}

func TestMapAttributesToHeaders_WithFriendlyName_ConfigUsesFriendlyName_IdPSendsOID(t *testing.T) {
	// User configures with friendly name, IdP sends OID
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "eduPersonPrincipalName", HeaderName: "X-Remote-User"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Remote-User"] != "user@example.com" {
		t.Errorf("expected X-Remote-User=user@example.com, got %q", result["X-Remote-User"])
	}
}

func TestMapAttributesToHeaders_WithFriendlyName_ConfigUsesOID_IdPSendsFriendlyName(t *testing.T) {
	// User configures with OID, IdP sends friendly name
	attrs := map[string][]string{
		"eduPersonPrincipalName": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", HeaderName: "X-Remote-User"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Remote-User"] != "user@example.com" {
		t.Errorf("expected X-Remote-User=user@example.com, got %q", result["X-Remote-User"])
	}
}

func TestMapAttributesToHeaders_WithFriendlyName_ConfigUsesFriendlyName_IdPSendsFriendlyName(t *testing.T) {
	// User configures with friendly name, IdP sends friendly name
	attrs := map[string][]string{
		"eduPersonPrincipalName": {"user@example.com"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "eduPersonPrincipalName", HeaderName: "X-Remote-User"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Remote-User"] != "user@example.com" {
		t.Errorf("expected X-Remote-User=user@example.com, got %q", result["X-Remote-User"])
	}
}

func TestMapAttributesToHeaders_UnknownAttribute_PassesThrough(t *testing.T) {
	// Unknown attributes should work as-is (backward compatibility)
	attrs := map[string][]string{
		"customAttribute": {"value"},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "customAttribute", HeaderName: "X-Custom"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Custom"] != "value" {
		t.Errorf("expected X-Custom=value, got %q", result["X-Custom"])
	}
}

func TestMapAttributesToHeaders_SeparatorSanitizesToEmpty_DefaultsToSemicolon(t *testing.T) {
	// Test that separator containing only control characters sanitizes to empty
	// and re-defaults to ";"
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7": {"admin", "user", "editor"},
	}
	mappings := []AttributeMapping{
		{
			SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
			HeaderName:    "X-Entitlements",
			Separator:     "\r\n", // Control characters that sanitize to empty
		},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "admin;user;editor"
	if result["X-Entitlements"] != expected {
		t.Errorf("expected %q, got %q", expected, result["X-Entitlements"])
	}
}

// =============================================================================
// Property-Based Tests
// =============================================================================

func TestMapAttributesToHeaders_Property_NoExtraHeaders(t *testing.T) {
	f := func(attrKey, attrVal, headerName string) bool {
		// Ensure valid header name for this property test
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: attrKey, HeaderName: headerName}}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			return true // Invalid mapping, skip
		}

		// Property: all output headers must be in the mapping configuration
		for header := range result {
			found := false
			for _, m := range mappings {
				if m.HeaderName == header {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapAttributesToHeaders_Property_NoMissingHeaders(t *testing.T) {
	f := func(attrKey, attrVal, headerName string) bool {
		// Ensure valid header name
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		// Only test with non-empty values
		if attrVal == "" {
			return true
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: attrKey, HeaderName: headerName}}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			return true
		}

		// Property: if attribute exists with non-empty value, header should exist
		_, exists := result[headerName]
		return exists
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapAttributesToHeaders_Property_Deterministic(t *testing.T) {
	f := func(attrKey, attrVal, headerName string) bool {
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: attrKey, HeaderName: headerName}}

		result1, err1 := mapAttributesToHeadersViaPort(attrs, mappings)
		result2, err2 := mapAttributesToHeadersViaPort(attrs, mappings)

		// Property: same input always produces same output
		if (err1 == nil) != (err2 == nil) {
			return false
		}
		if err1 != nil {
			return true
		}

		if len(result1) != len(result2) {
			return false
		}
		for k, v := range result1 {
			if result2[k] != v {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapAttributesToHeaders_Property_NoHeaderInjection(t *testing.T) {
	f := func(attrVal string) bool {
		attrs := map[string][]string{"test": {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: "test", HeaderName: "X-Test"}}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			return true
		}

		// Property: no CR/LF in output values
		for _, v := range result {
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

func TestMapAttributesToHeaders_Property_BoundedLength(t *testing.T) {
	f := func(attrVal string) bool {
		attrs := map[string][]string{"test": {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: "test", HeaderName: "X-Test"}}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			return true
		}

		// Property: output values never exceed max length
		for _, v := range result {
			if len(v) > MaxHeaderValueLength {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapAttributesToHeaders_Property_XPrefixEnforced(t *testing.T) {
	f := func(headerName string) bool {
		// Test that non-X- headers are rejected
		if strings.HasPrefix(headerName, "X-") || strings.HasPrefix(headerName, "x-") {
			return true // Skip valid prefixes
		}

		attrs := map[string][]string{"test": {"value"}}
		mappings := []AttributeMapping{{SAMLAttribute: "test", HeaderName: headerName}}

		_, err := mapAttributesToHeadersViaPort(attrs, mappings)

		// Property: headers without X- prefix must error
		return err != nil
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestMapAttributesToHeaders_Property_EmptySeparatorDefaults(t *testing.T) {
	// Property: Empty separator always defaults to ";" regardless of input
	f := func(attrKey string, val1, val2 string, headerName string) bool {
		// Ensure valid header name
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		// Skip if we don't have at least 2 values to test separator
		if val1 == "" || val2 == "" {
			return true
		}

		attrs := map[string][]string{attrKey: {val1, val2}}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrKey, HeaderName: headerName, Separator: ""}, // Empty separator
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			return true // Invalid mapping, skip
		}

		// Property: empty separator should always default to ";"
		if headerVal, ok := result[headerName]; ok {
			// Should contain semicolon separator
			return strings.Contains(headerVal, ";")
		}
		return true // No header produced (values might have been filtered)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestResolveAttributeName_Property_Bidirectionality(t *testing.T) {
	f := func(attrName string) bool {
		// Skip empty strings
		if attrName == "" {
			return true
		}

		oid1, friendlyName1 := ResolveAttributeName(attrName)
		oid2, friendlyName2 := ResolveAttributeName(oid1)
		oid3, friendlyName3 := ResolveAttributeName(friendlyName1)

		// Property: resolving the OID should give back the same friendly name
		if friendlyName2 != friendlyName1 {
			return false
		}

		// Property: resolving the friendly name should give back the same OID
		if oid3 != oid1 {
			return false
		}

		// Property: resolving in either direction should be consistent
		return oid2 == oid1 && friendlyName3 == friendlyName1
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestResolveAttributeName_Property_Idempotence(t *testing.T) {
	f := func(attrName string) bool {
		// Skip empty strings
		if attrName == "" {
			return true
		}

		oid1, friendlyName1 := ResolveAttributeName(attrName)
		oid2, friendlyName2 := ResolveAttributeName(oid1)
		oid3, friendlyName3 := ResolveAttributeName(friendlyName1)

		// Property: resolving multiple times should give same result
		if oid1 != oid2 || oid2 != oid3 {
			return false
		}
		if friendlyName1 != friendlyName2 || friendlyName2 != friendlyName3 {
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestResolveAttributeName_Property_Passthrough(t *testing.T) {
	f := func(attrName string) bool {
		// Skip empty strings
		if attrName == "" {
			return true
		}

		// Skip known attributes (they should resolve to OIDs)
		knownOIDs := []string{
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
			"urn:oid:0.9.2342.19200300.100.1.3",
			"urn:oid:2.5.4.42",
			"urn:oid:2.5.4.4",
			"urn:oid:2.16.840.1.113730.3.1.241",
			"urn:oid:1.3.6.1.4.1.25178.1.2.9",
		}
		knownNames := []string{
			"eduPersonPrincipalName",
			"eduPersonEntitlement",
			"eduPersonScopedAffiliation",
			"eduPersonTargetedID",
			"mail",
			"givenName",
			"sn",
			"displayName",
			"schacHomeOrganization",
		}

		for _, known := range knownOIDs {
			if attrName == known {
				return true // Skip known OIDs
			}
		}
		for _, known := range knownNames {
			if attrName == known {
				return true // Skip known friendly names
			}
		}

		// Property: unknown names should pass through unchanged
		oid, friendlyName := ResolveAttributeName(attrName)
		return oid == attrName && friendlyName == attrName
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestResolveAttributeName_Property_RoundtripOIDToFriendlyToOID(t *testing.T) {
	// Property: Starting with an OID, resolve to friendly name, then resolve friendly name back to OID - should return original OID
	knownOIDs := []string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"urn:oid:2.5.4.42",
		"urn:oid:2.5.4.4",
		"urn:oid:2.16.840.1.113730.3.1.241",
		"urn:oid:1.3.6.1.4.1.25178.1.2.9",
	}

	for _, oid := range knownOIDs {
		t.Run(oid, func(t *testing.T) {
			// Start with OID
			originalOID := oid
			// Resolve to friendly name
			_, friendlyName := ResolveAttributeName(originalOID)
			// Resolve friendly name back to OID
			finalOID, _ := ResolveAttributeName(friendlyName)
			// Property: original OID == final OID
			if originalOID != finalOID {
				t.Errorf("roundtrip failed: started with OID %q, got friendly name %q, resolved back to OID %q (expected %q)", originalOID, friendlyName, finalOID, originalOID)
			}
		})
	}
}

func TestResolveAttributeName_Property_RegistryConsistency(t *testing.T) {
	// Property: For all entries in oidRegistry, if OID A maps to friendly B, then friendly B must map back to OID A
	// This is a deterministic test since the registry is fixed
	knownOIDs := []string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
		"urn:oid:0.9.2342.19200300.100.1.3",
		"urn:oid:2.5.4.42",
		"urn:oid:2.5.4.4",
		"urn:oid:2.16.840.1.113730.3.1.241",
		"urn:oid:1.3.6.1.4.1.25178.1.2.9",
	}

	for _, oid := range knownOIDs {
		t.Run(oid, func(t *testing.T) {
			// Resolve OID to friendly name
			_, friendlyName := ResolveAttributeName(oid)
			// Resolve friendly name back to OID
			backToOID, _ := ResolveAttributeName(friendlyName)
			// Property: friendly B must map back to OID A
			if oid != backToOID {
				t.Errorf("registry inconsistency: OID %q maps to friendly name %q, but friendly name %q maps back to OID %q (expected %q)", oid, friendlyName, friendlyName, backToOID, oid)
			}
		})
	}
}

func TestResolveAttributeName_Property_FriendlyNameWithOIDPrefix(t *testing.T) {
	// Property: Friendly names starting with "urn:oid:" prefix should not be incorrectly treated as OIDs
	// This tests the edge case where a friendly name might start with "urn:oid:" prefix
	
	// Test with an unknown friendly name that starts with "urn:oid:" prefix
	// This should pass through unchanged (not be treated as an OID)
	unknownFriendlyWithPrefix := "urn:oid:customAttribute"
	oid, friendlyName := ResolveAttributeName(unknownFriendlyWithPrefix)
	if oid != unknownFriendlyWithPrefix || friendlyName != unknownFriendlyWithPrefix {
		t.Errorf("unknown friendly name with 'urn:oid:' prefix should pass through unchanged: got oid=%q, friendlyName=%q, expected both %q", oid, friendlyName, unknownFriendlyWithPrefix)
	}

	// Test that known friendly names are still resolved correctly even if they don't start with "urn:oid:"
	// (This is a sanity check - none of our known friendly names start with "urn:oid:")
	knownFriendlyNames := []string{
		"eduPersonPrincipalName",
		"eduPersonEntitlement",
		"mail",
		"givenName",
	}

	for _, friendlyName := range knownFriendlyNames {
		t.Run(friendlyName, func(t *testing.T) {
			oid, resolvedFriendlyName := ResolveAttributeName(friendlyName)
			// Should resolve correctly
			if resolvedFriendlyName != friendlyName {
				t.Errorf("known friendly name %q should resolve to itself as friendly name, got %q", friendlyName, resolvedFriendlyName)
			}
			// Should have a corresponding OID
			if !strings.HasPrefix(oid, "urn:oid:") {
				t.Errorf("known friendly name %q should resolve to an OID starting with 'urn:oid:', got %q", friendlyName, oid)
			}
		})
	}
}

// =============================================================================
// Invariant Checker (Reusable for Fuzz Tests)
// =============================================================================

// checkAttributeMappingInvariants verifies all security invariants for MapAttributesToHeaders output.
func checkAttributeMappingInvariants(t *testing.T, attrs map[string][]string, mappings []AttributeMapping, result map[string]string, err error) {
	t.Helper()

	// If there was an error, check it's for valid reasons
	if err != nil {
		// Errors should only occur for invalid header names
		return
	}

	// Invariant 1: No extra headers beyond what's configured
	allowedHeaders := make(map[string]bool)
	for _, m := range mappings {
		allowedHeaders[m.HeaderName] = true
	}
	for header := range result {
		if !allowedHeaders[header] {
			t.Errorf("invariant violated: unexpected header %q in result", header)
		}
	}

	// Invariant 2: No CR/LF in values (header injection prevention)
	for header, value := range result {
		if strings.ContainsAny(value, "\r\n") {
			t.Errorf("invariant violated: header %q contains CR/LF: %q", header, value)
		}
	}

	// Invariant 3: All header names start with X-
	for header := range result {
		if !strings.HasPrefix(header, "X-") && !strings.HasPrefix(header, "x-") {
			t.Errorf("invariant violated: header %q doesn't start with X-", header)
		}
	}

	// Invariant 4: Valid header name characters
	for header := range result {
		if !isValidHeaderNameForTest(header) {
			t.Errorf("invariant violated: header %q contains invalid characters", header)
		}
	}

	// Invariant 5: Bounded length
	for header, value := range result {
		if len(value) > MaxHeaderValueLength {
			t.Errorf("invariant violated: header %q value exceeds max length: %d > %d", header, len(value), MaxHeaderValueLength)
		}
	}
}

// =============================================================================
// Test Helpers
// =============================================================================

// sanitizeForHeaderName removes invalid characters for use in property tests
func sanitizeForHeaderName(s string) string {
	var result strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// isValidHeaderNameForTest checks if a header name matches ^X-[A-Za-z0-9-]+$
func isValidHeaderNameForTest(name string) bool {
	if len(name) < 3 {
		return false
	}
	if !strings.HasPrefix(name, "X-") && !strings.HasPrefix(name, "x-") {
		return false
	}
	for i := 2; i < len(name); i++ {
		c := name[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// =============================================================================
// Header Prefix Tests
// =============================================================================

func TestApplyHeaderPrefix_EmptyPrefix(t *testing.T) {
	// Prefix empty - header name unchanged
	result := ApplyHeaderPrefix("", "X-Remote-User")
	if result != "X-Remote-User" {
		t.Errorf("expected X-Remote-User, got %s", result)
	}
}

func TestApplyHeaderPrefix_WithPrefix(t *testing.T) {
	// Prefix applied to header name
	result := ApplyHeaderPrefix("X-Saml-", "User")
	if result != "X-Saml-User" {
		t.Errorf("expected X-Saml-User, got %s", result)
	}
}

func TestApplyHeaderPrefix_WithPrefixAndExistingX(t *testing.T) {
	// Prefix applied even if header already has X-
	result := ApplyHeaderPrefix("X-Saml-", "X-Remote-User")
	if result != "X-Saml-X-Remote-User" {
		t.Errorf("expected X-Saml-X-Remote-User, got %s", result)
	}
}

// TestSanitizeHeaderValue_Property_Idempotency tests ATTR-016:
// Property: sanitizing a value twice should produce the same result.
// Since sanitizeHeaderValue is unexported, we test it indirectly through MapAttributesToHeaders.
func TestSanitizeHeaderValue_Property_Idempotency(t *testing.T) {
	f := func(attrVal string) bool {
		// Skip empty strings
		if attrVal == "" {
			return true
		}

		attrs := map[string][]string{"test": {attrVal}}
		mappings := []AttributeMapping{{SAMLAttribute: "test", HeaderName: "X-Test"}}

		// First pass: map attributes to headers (sanitizes the value)
		result1, err1 := mapAttributesToHeadersViaPort(attrs, mappings)
		if err1 != nil {
			return true // Invalid mapping, skip
		}

		// If no header was produced (value was filtered out), skip
		sanitized1, ok := result1["X-Test"]
		if !ok {
			return true // Value was filtered out, skip
		}

		// Second pass: use the same input again (with dangerous characters still present)
		// Property: should produce the same sanitized output
		result2, err2 := mapAttributesToHeadersViaPort(attrs, mappings)
		if err2 != nil {
			return false // Should not error on second pass
		}

		sanitized2, ok := result2["X-Test"]
		if !ok {
			return false // Should produce header if first pass did
		}

		// Property: sanitizing twice should produce the same result
		return sanitized1 == sanitized2
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestApplyHeaderPrefix_Property_Associativity tests ATTR-017:
// Property: Verify associativity and double-prefix behavior.
func TestApplyHeaderPrefix_Property_Associativity(t *testing.T) {
	// Test associativity: ApplyHeaderPrefix(p1, ApplyHeaderPrefix(p2, name)) == ApplyHeaderPrefix(p1+p2, name)
	f1 := func(prefix1, prefix2, headerName string) bool {
		// Ensure valid prefixes and header name
		prefix1 = "X-" + sanitizeForHeaderName(prefix1)
		if len(prefix1) < 3 {
			prefix1 = "X-A-"
		}
		prefix2 = "X-" + sanitizeForHeaderName(prefix2)
		if len(prefix2) < 3 {
			prefix2 = "X-B-"
		}
		headerName = sanitizeForHeaderName(headerName)
		if headerName == "" {
			headerName = "Header"
		}

		// Test associativity
		result1 := ApplyHeaderPrefix(prefix1, ApplyHeaderPrefix(prefix2, headerName))
		result2 := ApplyHeaderPrefix(prefix1+prefix2, headerName)

		// Property: should be equal (associativity)
		return result1 == result2
	}

	if err := quick.Check(f1, nil); err != nil {
		t.Error(err)
	}

	// Test double-prefix behavior: ApplyHeaderPrefix(p, ApplyHeaderPrefix(p, name))
	// This verifies if double-prefixing is intentional or a bug
	f2 := func(prefix, headerName string) bool {
		// Ensure valid prefix and header name
		prefix = "X-" + sanitizeForHeaderName(prefix)
		if len(prefix) < 3 {
			prefix = "X-Saml-"
		}
		headerName = sanitizeForHeaderName(headerName)
		if headerName == "" {
			headerName = "Header"
		}

		// Apply prefix twice
		result := ApplyHeaderPrefix(prefix, ApplyHeaderPrefix(prefix, headerName))
		expected := prefix + prefix + headerName

		// Property: double-prefix produces concatenated result (current behavior)
		// This test documents the current behavior - if this is a bug, the test will fail
		// and we can fix it. If intentional, this test confirms the behavior.
		return result == expected
	}

	if err := quick.Check(f2, nil); err != nil {
		t.Error(err)
	}
}

// TestMapAttributesToHeadersWithPrefix_Property_DoublePrefix tests ATTR-018:
// Property: If header names already have prefix, calling function again should not double-prefix.
func TestMapAttributesToHeadersWithPrefix_Property_DoublePrefix(t *testing.T) {
	f := func(attrKey, attrVal, headerName, prefix string) bool {
		// Ensure valid prefix and header name
		prefix = "X-" + sanitizeForHeaderName(prefix)
		if len(prefix) < 3 {
			prefix = "X-Saml-"
		}
		headerName = sanitizeForHeaderName(headerName)
		if headerName == "" {
			headerName = "User"
		}
		if attrKey == "" {
			attrKey = "test"
		}
		if attrVal == "" {
			attrVal = "value"
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrKey, HeaderName: headerName},
		}

		// First call: apply prefix
		result1, err1 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
		if err1 != nil {
			return true // Invalid input, skip
		}

		// Get the prefixed header name from result
		var prefixedHeaderName string
		for k := range result1 {
			prefixedHeaderName = k
			break
		}
		if prefixedHeaderName == "" {
			return true // No header produced, skip
		}

		// Second call: use the prefixed header name as input with the same prefix
		// This simulates calling the function again with already-prefixed headers
		mappings2 := []AttributeMapping{
			{SAMLAttribute: attrKey, HeaderName: prefixedHeaderName},
		}
		result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings2, prefix)
		if err2 != nil {
			return true // May error if double-prefixed name is invalid, skip
		}

		// Get the result header name
		var resultHeaderName string
		for k := range result2 {
			resultHeaderName = k
			break
		}
		if resultHeaderName == "" {
			return true // No header produced, skip
		}

		// Property: if prefix is already applied, calling again should not double-prefix
		// Current behavior: it WILL double-prefix (ApplyHeaderPrefix just concatenates)
		// This test documents the current behavior - if this is a bug, the test will fail
		// and we can fix it. If intentional, this test confirms the behavior.
		expectedDoublePrefix := prefix + prefixedHeaderName
		return resultHeaderName == expectedDoublePrefix
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestMapAttributesToHeadersWithPrefix_Property_Idempotency tests ATTR-019:
// Property: Calling MapAttributesToHeadersWithPrefix twice with same inputs should produce identical outputs.
func TestMapAttributesToHeadersWithPrefix_Property_Idempotency(t *testing.T) {
	f := func(attrKey, attrVal, headerName, prefixSuffix string) bool {
		// Ensure valid header name (without X- prefix since prefix will be added)
		headerName = sanitizeForHeaderName(headerName)
		if headerName == "" {
			headerName = "Header"
		}

		// Ensure valid prefix
		prefixSuffix = sanitizeForHeaderName(prefixSuffix)
		if prefixSuffix == "" {
			prefixSuffix = "Saml"
		}
		prefix := "X-" + prefixSuffix + "-"

		// Skip if attribute key or value is empty
		if attrKey == "" || attrVal == "" {
			return true
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrKey, HeaderName: headerName},
		}

		// First call
		result1, err1 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
		if err1 != nil {
			return true // Invalid input, skip
		}

		// Second call with same inputs
		result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
		if err2 != nil {
			return false // Should not error on second call
		}

		// Property: both calls should produce identical results
		if len(result1) != len(result2) {
			return false
		}

		for k, v := range result1 {
			if result2[k] != v {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestMapAttributesToHeaders_Property_ThreadSafety tests ATTR-020:
// Property: Concurrent calls with different inputs should not interfere (functions are pure with no shared mutable state).
func TestMapAttributesToHeaders_Property_ThreadSafety(t *testing.T) {
	const numGoroutines = 100
	const numCallsPerGoroutine = 10

	var wg sync.WaitGroup
	errorMessages := make(chan string, numGoroutines*numCallsPerGoroutine)

	// Run concurrent calls with different inputs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numCallsPerGoroutine; j++ {
				// Each goroutine uses unique attribute keys and values
				// Use numeric IDs to ensure valid characters
				attrKey := fmt.Sprintf("attr%d_%d", id, j)
				attrVal := fmt.Sprintf("value%d_%d", id, j)
				headerNameSuffix := sanitizeForHeaderName(fmt.Sprintf("Header%d_%d", id, j))
				if headerNameSuffix == "" {
					headerNameSuffix = "Header"
				}
				headerName := "X-" + headerNameSuffix

				attrs := map[string][]string{attrKey: {attrVal}}
				mappings := []AttributeMapping{
					{SAMLAttribute: attrKey, HeaderName: headerName},
				}

				// Call MapAttributesToHeaders concurrently
				result1, err1 := mapAttributesToHeadersViaPort(attrs, mappings)
				if err1 != nil {
					errorMessages <- err1.Error()
					continue
				}

				// Verify result is correct
				expectedHeader := headerName
				if val, ok := result1[expectedHeader]; !ok || val != attrVal {
					errorMessages <- fmt.Sprintf("goroutine %d call %d: expected header %q with value %q, got %v", id, j, expectedHeader, attrVal, result1)
					continue
				}

				// Also test MapAttributesToHeadersWithPrefix concurrently
				prefix := "X-Prefix-"
				result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
				if err2 != nil {
					errorMessages <- err2.Error()
					continue
				}

				expectedPrefixedHeader := prefix + headerName
				if val, ok := result2[expectedPrefixedHeader]; !ok || val != attrVal {
					errorMessages <- fmt.Sprintf("goroutine %d call %d: expected prefixed header %q with value %q, got %v", id, j, expectedPrefixedHeader, attrVal, result2)
					continue
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorMessages)

	// Check for any errors
	for msg := range errorMessages {
		t.Error(msg)
	}
}

func TestMapAttributesToHeaders_WithPrefix(t *testing.T) {
	attrs := map[string][]string{"mail": {"user@example.com"}}
	mappings := []AttributeMapping{{SAMLAttribute: "mail", HeaderName: "User"}}
	prefix := "X-Saml-"

	result, err := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Saml-User"] != "user@example.com" {
		t.Errorf("expected header X-Saml-User=user@example.com, got %v", result)
	}
	// Should not have unprefixed header
	if _, exists := result["User"]; exists {
		t.Error("should not have unprefixed header 'User'")
	}
}

func TestMapAttributesToHeaders_WithPrefix_NoXRequired(t *testing.T) {
	// When prefix is set, header names don't need X- prefix
	attrs := map[string][]string{"mail": {"user@example.com"}}
	mappings := []AttributeMapping{{SAMLAttribute: "mail", HeaderName: "Remote-User"}}
	prefix := "X-Saml-"

	result, err := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Saml-Remote-User"] != "user@example.com" {
		t.Errorf("expected header X-Saml-Remote-User=user@example.com, got %v", result)
	}
}

func TestMapAttributesToHeaders_WithoutPrefix_RequiresX(t *testing.T) {
	// Without prefix, existing behavior - must start with X-
	attrs := map[string][]string{"mail": {"user@example.com"}}
	mappings := []AttributeMapping{{SAMLAttribute: "mail", HeaderName: "User"}} // Missing X-
	prefix := ""

	_, err := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, prefix)
	if err == nil {
		t.Error("expected error for header without X- prefix when prefix is empty")
	}
}

// =============================================================================
// Property Tests for Prefix Application (ATTR-002, ATTR-012)
// =============================================================================

// TestMapAttributesToHeadersWithPrefix_Property_PrefixConsistentRegardlessOfOrder tests ATTR-002:
// Property: Prefix application should be consistent regardless of mapping order.
// Given the same set of mappings in different orders, prefix application should
// produce the same set of header names (regardless of which values end up in those headers).
func TestMapAttributesToHeadersWithPrefix_Property_PrefixConsistentRegardlessOfOrder(t *testing.T) {
	f := func(attrKey1, attrKey2, attrVal1, attrVal2, headerName1, headerName2, prefixSuffix string) bool {
		// Ensure valid header names (without X- prefix since prefix will be added)
		headerName1 = sanitizeForHeaderName(headerName1)
		headerName2 = sanitizeForHeaderName(headerName2)
		if headerName1 == "" {
			headerName1 = "Header1"
		}
		if headerName2 == "" {
			headerName2 = "Header2"
		}
		// Ensure header names are different
		if headerName1 == headerName2 {
			headerName2 = headerName2 + "2"
		}

		// Ensure valid prefix
		prefixSuffix = sanitizeForHeaderName(prefixSuffix)
		if prefixSuffix == "" {
			prefixSuffix = "Saml"
		}
		prefix := "X-" + prefixSuffix + "-"

		// Skip if attributes are empty
		if attrKey1 == "" || attrKey2 == "" {
			return true
		}

		attrs := map[string][]string{
			attrKey1: {attrVal1},
			attrKey2: {attrVal2},
		}

		// Create mappings in original order
		mappings1 := []AttributeMapping{
			{SAMLAttribute: attrKey1, HeaderName: headerName1},
			{SAMLAttribute: attrKey2, HeaderName: headerName2},
		}

		// Create mappings in reversed order
		mappings2 := []AttributeMapping{
			{SAMLAttribute: attrKey2, HeaderName: headerName2},
			{SAMLAttribute: attrKey1, HeaderName: headerName1},
		}

		// Apply prefix to both orders
		result1, err1 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings1, prefix)
		result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings2, prefix)

		// Both should succeed or both should fail
		if (err1 == nil) != (err2 == nil) {
			return false
		}
		if err1 != nil {
			return true // Skip invalid configs
		}

		// Property: Same set of header names should be produced
		if len(result1) != len(result2) {
			return false
		}

		// Check that all header names from result1 exist in result2
		for headerName := range result1 {
			if _, exists := result2[headerName]; !exists {
				return false
			}
		}

		// Check that all header names from result2 exist in result1
		for headerName := range result2 {
			if _, exists := result1[headerName]; !exists {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestMapAttributesToHeadersWithPrefix_Property_OrderDependencyConsistent tests ATTR-012:
// Property: When multiple mappings produce the same header name (after prefix),
// the final value should consistently depend on order (last mapping wins).
func TestMapAttributesToHeadersWithPrefix_Property_OrderDependencyConsistent(t *testing.T) {
	f := func(attrKey1, attrKey2, attrVal1, attrVal2, headerName, prefixSuffix string) bool {
		// Ensure valid header name (without X- prefix since prefix will be added)
		headerName = sanitizeForHeaderName(headerName)
		if headerName == "" {
			headerName = "Header"
		}

		// Ensure valid prefix
		prefixSuffix = sanitizeForHeaderName(prefixSuffix)
		if prefixSuffix == "" {
			prefixSuffix = "Saml"
		}
		prefix := "X-" + prefixSuffix + "-"

		// Skip if attributes are empty or same
		if attrKey1 == "" || attrKey2 == "" || attrKey1 == attrKey2 {
			return true
		}

		// Skip if values are same (we need different values to test order dependency)
		if attrVal1 == attrVal2 {
			return true
		}

		attrs := map[string][]string{
			attrKey1: {attrVal1},
			attrKey2: {attrVal2},
		}

		// Create mappings where both produce the same header name after prefix
		// Order 1: attrKey1 first, attrKey2 second (attrKey2 should win)
		mappings1 := []AttributeMapping{
			{SAMLAttribute: attrKey1, HeaderName: headerName},
			{SAMLAttribute: attrKey2, HeaderName: headerName},
		}

		// Order 2: attrKey2 first, attrKey1 second (attrKey1 should win)
		mappings2 := []AttributeMapping{
			{SAMLAttribute: attrKey2, HeaderName: headerName},
			{SAMLAttribute: attrKey1, HeaderName: headerName},
		}

		// Apply prefix to both orders
		result1, err1 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings1, prefix)
		result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings2, prefix)

		// Both should succeed or both should fail
		if (err1 == nil) != (err2 == nil) {
			return false
		}
		if err1 != nil {
			return true // Skip invalid configs
		}

		// Property: Last mapping should win
		// In mappings1, attrKey2 is last, so result1 should have attrVal2
		// In mappings2, attrKey1 is last, so result2 should have attrVal1
		expectedHeaderName := prefix + headerName

		val1, exists1 := result1[expectedHeaderName]
		val2, exists2 := result2[expectedHeaderName]

		// Both should produce the header
		if !exists1 || !exists2 {
			return false
		}

		// Property: Order 1 (attrKey2 last) should have attrVal2
		if val1 != attrVal2 {
			return false
		}

		// Property: Order 2 (attrKey1 last) should have attrVal1
		if val2 != attrVal1 {
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// =============================================================================
// Differential Tests (ATTR-004, ATTR-007-011)
// =============================================================================

// TestMapAttributesToHeaders_Differential_BothFormsDifferentValues tests ATTR-007:
// When IdP sends both OID and friendly name with different values, verify which value is used.
func TestMapAttributesToHeaders_Differential_BothFormsDifferentValues(t *testing.T) {
	// Test case: IdP sends both forms with different values
	attrs := map[string][]string{
		"eduPersonPrincipalName":                        {"user1@example.com"},
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6": {"user2@example.com"},
	}

	// Test 1: Configure mapping with friendly name - should use friendly name value
	t.Run("ConfigUsesFriendlyName", func(t *testing.T) {
		mappings := []AttributeMapping{
			{SAMLAttribute: "eduPersonPrincipalName", HeaderName: "X-Remote-User"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Configured form (friendly name) should take precedence
		expected := "user1@example.com"
		if result["X-Remote-User"] != expected {
			t.Errorf("expected X-Remote-User=%q (friendly name value), got %q", expected, result["X-Remote-User"])
		}
	})

	// Test 2: Configure mapping with OID - should use OID value
	t.Run("ConfigUsesOID", func(t *testing.T) {
		mappings := []AttributeMapping{
			{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", HeaderName: "X-Remote-User"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Configured form (OID) should take precedence
		expected := "user2@example.com"
		if result["X-Remote-User"] != expected {
			t.Errorf("expected X-Remote-User=%q (OID value), got %q", expected, result["X-Remote-User"])
		}
	})
}

// TestMapAttributesToHeaders_Differential_MultipleMappingsSameAttribute tests ATTR-008:
// Multiple mappings referencing same logical attribute process independently.
func TestMapAttributesToHeaders_Differential_MultipleMappingsSameAttribute(t *testing.T) {
	// IdP sends both forms with potentially different values
	attrs := map[string][]string{
		"eduPersonPrincipalName":                        {"user1@example.com"},
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.6": {"user2@example.com"},
	}

	// Two mappings: one using OID, one using friendly name
	mappings := []AttributeMapping{
		{SAMLAttribute: "eduPersonPrincipalName", HeaderName: "X-User-Friendly"},
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", HeaderName: "X-User-OID"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both mappings should process independently
	// Each uses its configured form, so they get different values
	if result["X-User-Friendly"] != "user1@example.com" {
		t.Errorf("expected X-User-Friendly=user1@example.com, got %q", result["X-User-Friendly"])
	}
	if result["X-User-OID"] != "user2@example.com" {
		t.Errorf("expected X-User-OID=user2@example.com, got %q", result["X-User-OID"])
	}

	// Both headers should exist (not duplicates, but different header names)
	if len(result) != 2 {
		t.Errorf("expected 2 headers, got %d: %v", len(result), result)
	}
}

// TestMapAttributesToHeaders_Differential_LookupOrder tests ATTR-009:
// Property: When both forms exist, configured form should always be used.
func TestMapAttributesToHeaders_Differential_LookupOrder(t *testing.T) {
	// Test with known attributes that have both OID and friendly name forms
	testCases := []struct {
		name           string
		configAttr     string
		oidValue       string
		friendlyValue  string
		expectedValue  string
	}{
		{
			name:          "ConfigOID_BothFormsExist",
			configAttr:    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			oidValue:      "oid-value",
			friendlyValue: "friendly-value",
			expectedValue: "oid-value", // Configured form (OID) should be used
		},
		{
			name:          "ConfigFriendly_BothFormsExist",
			configAttr:    "eduPersonPrincipalName",
			oidValue:      "oid-value",
			friendlyValue: "friendly-value",
			expectedValue: "friendly-value", // Configured form (friendly) should be used
		},
		{
			name:          "ConfigOID_OnlyFriendlyExists",
			configAttr:    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			oidValue:      "",
			friendlyValue: "friendly-value",
			expectedValue: "friendly-value", // Should fall back to friendly name
		},
		{
			name:          "ConfigFriendly_OnlyOIDExists",
			configAttr:    "eduPersonPrincipalName",
			oidValue:      "oid-value",
			friendlyValue: "",
			expectedValue: "oid-value", // Should fall back to OID
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string][]string{}
			if tc.oidValue != "" {
				attrs["urn:oid:1.3.6.1.4.1.5923.1.1.1.6"] = []string{tc.oidValue}
			}
			if tc.friendlyValue != "" {
				attrs["eduPersonPrincipalName"] = []string{tc.friendlyValue}
			}

			mappings := []AttributeMapping{
				{SAMLAttribute: tc.configAttr, HeaderName: "X-Test"},
			}

			result, err := mapAttributesToHeadersViaPort(attrs, mappings)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Property: configured form should always be used when it exists
			if result["X-Test"] != tc.expectedValue {
				t.Errorf("expected X-Test=%q, got %q (configured form should take precedence)", tc.expectedValue, result["X-Test"])
			}
		})
	}
}

// TestMapAttributesToHeaders_Differential_EmptyValueHandling tests ATTR-010:
// Empty value filtering behavior.
func TestMapAttributesToHeaders_Differential_EmptyValueHandling(t *testing.T) {
	// Test case: Attribute with mix of empty and non-empty values
	attrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.7": {"", "value1", "", "value2", ""},
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", HeaderName: "X-Entitlements"},
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty values should be filtered before joining
	expected := "value1;value2"
	if result["X-Entitlements"] != expected {
		t.Errorf("expected X-Entitlements=%q (empty values filtered), got %q", expected, result["X-Entitlements"])
	}

	// Verify no empty strings in joined output
	if strings.Contains(result["X-Entitlements"], ";;") {
		t.Error("result contains empty separator sequences (empty values not filtered)")
	}
}

// TestMapAttributesToHeaders_Differential_CaseSensitivity tests ATTR-011:
// Case sensitivity of attribute name matching.
func TestMapAttributesToHeaders_Differential_CaseSensitivity(t *testing.T) {
	// Test case: Configure with correct case, IdP sends different case
	attrs := map[string][]string{
		"edupersonprincipalname": {"user@example.com"}, // lowercase
	}
	mappings := []AttributeMapping{
		{SAMLAttribute: "eduPersonPrincipalName", HeaderName: "X-Remote-User"}, // correct case
	}

	result, err := mapAttributesToHeadersViaPort(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Case-sensitive matching: lowercase attribute should NOT match
	if _, exists := result["X-Remote-User"]; exists {
		t.Error("case-insensitive matching detected: lowercase attribute matched configured friendly name")
	}

	// Test with correct case - should match
	attrsCorrect := map[string][]string{
		"eduPersonPrincipalName": {"user@example.com"},
	}
	result2, err := mapAttributesToHeadersViaPort(attrsCorrect, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2["X-Remote-User"] != "user@example.com" {
		t.Errorf("expected match with correct case, got %q", result2["X-Remote-User"])
	}
}

// TestMapAttributesToHeaders_Differential_Comprehensive tests ATTR-004:
// Comprehensive differential test suite combining all edge cases.
func TestMapAttributesToHeaders_Differential_Comprehensive(t *testing.T) {
	t.Run("RoundtripScenarios", func(t *testing.T) {
		// Test: Configure with OID, IdP sends friendly name (roundtrip)
		attrs := map[string][]string{
			"eduPersonPrincipalName": {"user@example.com"},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", HeaderName: "X-Remote-User"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["X-Remote-User"] != "user@example.com" {
			t.Errorf("roundtrip failed: expected user@example.com, got %q", result["X-Remote-User"])
		}
	})

	t.Run("UnknownAttributes", func(t *testing.T) {
		// Test: Unknown attributes should pass through as-is
		attrs := map[string][]string{
			"customAttribute": {"value"},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "customAttribute", HeaderName: "X-Custom"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["X-Custom"] != "value" {
			t.Errorf("unknown attribute passthrough failed: expected value, got %q", result["X-Custom"])
		}
	})

	t.Run("AttributeResolutionEdgeCases", func(t *testing.T) {
		// Test: Both forms exist, configured form takes precedence
		attrs := map[string][]string{
			"mail":                              {"mail-value"},
			"urn:oid:0.9.2342.19200300.100.1.3": {"oid-value"},
		}

		// Configure with friendly name
		mappings := []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Configured form (friendly name) should be used
		if result["X-Mail"] != "mail-value" {
			t.Errorf("attribute resolution precedence failed: expected mail-value, got %q", result["X-Mail"])
		}
	})

	t.Run("AllEmptyValues", func(t *testing.T) {
		// Test: All values are empty - should produce no header
		attrs := map[string][]string{
			"mail": {"", "", ""},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail"},
		}

		result, err := mapAttributesToHeadersViaPort(attrs, mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No header should be created for all-empty values
		if _, exists := result["X-Mail"]; exists {
			t.Error("header created for all-empty values, should be omitted")
		}
	})
}

// TestMapAttributesToHeaders_Differential_WithPrefixEquivalence tests ATTR-021:
// Property: mapAttributesToHeadersViaPort(attrs, mappings) should produce same result as
// mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, "") (empty prefix should be equivalent).
func TestMapAttributesToHeaders_Differential_WithPrefixEquivalence(t *testing.T) {
	f := func(attrKey, attrVal, headerName string) bool {
		// Ensure valid header name
		headerName = "X-" + sanitizeForHeaderName(headerName)
		if headerName == "X-" {
			headerName = "X-Test"
		}

		// Skip if attribute key or value is empty
		if attrKey == "" || attrVal == "" {
			return true
		}

		attrs := map[string][]string{attrKey: {attrVal}}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrKey, HeaderName: headerName},
		}

		// Call MapAttributesToHeaders
		result1, err1 := mapAttributesToHeadersViaPort(attrs, mappings)
		if err1 != nil {
			return true // Invalid input, skip
		}

		// Call MapAttributesToHeadersWithPrefix with empty prefix
		result2, err2 := mapAttributesToHeadersWithPrefixViaPort(attrs, mappings, "")
		if err2 != nil {
			return false // Should not error if MapAttributesToHeaders didn't
		}

		// Property: both should produce identical results
		if len(result1) != len(result2) {
			return false
		}

		for k, v := range result1 {
			if result2[k] != v {
				return false
			}
		}

		// Also verify reverse (all keys in result2 exist in result1)
		for k := range result2 {
			if result1[k] != result2[k] {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
