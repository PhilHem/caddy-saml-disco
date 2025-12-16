//go:build unit

package caddysamldisco

import (
	"strings"
	"testing"
	"testing/quick"
)

// =============================================================================
// Unit Tests
// =============================================================================

func TestMapAttributesToHeaders_EmptyMappings(t *testing.T) {
	attrs := map[string][]string{
		"email": {"user@example.com"},
	}
	mappings := []AttributeMapping{}

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	_, err := MapAttributesToHeaders(attrs, mappings)
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

	_, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
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

	result, err := MapAttributesToHeaders(attrs, mappings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["X-Custom"] != "value" {
		t.Errorf("expected X-Custom=value, got %q", result["X-Custom"])
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

		result, err := MapAttributesToHeaders(attrs, mappings)
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

		result, err := MapAttributesToHeaders(attrs, mappings)
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

		result1, err1 := MapAttributesToHeaders(attrs, mappings)
		result2, err2 := MapAttributesToHeaders(attrs, mappings)

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

		result, err := MapAttributesToHeaders(attrs, mappings)
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

		result, err := MapAttributesToHeaders(attrs, mappings)
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

		_, err := MapAttributesToHeaders(attrs, mappings)

		// Property: headers without X- prefix must error
		return err != nil
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
		friendlyName3, oid3 := ResolveAttributeName(friendlyName1)

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
