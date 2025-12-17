//go:build unit

package domain

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// Cycle 1: Verify ScopeInfo struct exists
func TestScopeInfo_Interface(t *testing.T) {
	// Verify struct can be created
	scope := ScopeInfo{
		Value:  "example.edu",
		Regexp: false,
	}

	if scope.Value != "example.edu" {
		t.Errorf("ScopeInfo.Value = %q, want %q", scope.Value, "example.edu")
	}
	if scope.Regexp != false {
		t.Errorf("ScopeInfo.Regexp = %v, want false", scope.Regexp)
	}

	// Test regex scope
	regexScope := ScopeInfo{
		Value:  ".*\\.partner\\.edu",
		Regexp: true,
	}

	if regexScope.Value != ".*\\.partner\\.edu" {
		t.Errorf("ScopeInfo.Value = %q, want %q", regexScope.Value, ".*\\.partner\\.edu")
	}
	if regexScope.Regexp != true {
		t.Errorf("ScopeInfo.Regexp = %v, want true", regexScope.Regexp)
	}
}

// Cycle 2: ExtractScope pure function tests
func TestExtractScope_Simple(t *testing.T) {
	got := ExtractScope("user@example.edu")
	want := "example.edu"
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "user@example.edu", got, want)
	}
}

func TestExtractScope_NoAt(t *testing.T) {
	got := ExtractScope("admin")
	want := ""
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "admin", got, want)
	}
}

func TestExtractScope_MultipleAt(t *testing.T) {
	// According to SAML spec, scoped attributes should have format user@scope
	// But we handle edge case: take everything after first @
	got := ExtractScope("user@sub@example.edu")
	want := "sub@example.edu"
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "user@sub@example.edu", got, want)
	}
}

func TestExtractScope_EmptyValue(t *testing.T) {
	got := ExtractScope("")
	want := ""
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "", got, want)
	}
}

func TestExtractScope_OnlyAt(t *testing.T) {
	got := ExtractScope("@")
	want := ""
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "@", got, want)
	}
}

func TestExtractScope_StartsWithAt(t *testing.T) {
	got := ExtractScope("@example.edu")
	want := "example.edu"
	if got != want {
		t.Errorf("ExtractScope(%q) = %q, want %q", "@example.edu", got, want)
	}
}

// Cycle 3: IsScopedAttribute function tests
func TestIsScopedAttribute_EPPN(t *testing.T) {
	if !IsScopedAttribute("eduPersonPrincipalName") {
		t.Error("IsScopedAttribute(\"eduPersonPrincipalName\") = false, want true")
	}
}

func TestIsScopedAttribute_ScopedAffiliation(t *testing.T) {
	if !IsScopedAttribute("eduPersonScopedAffiliation") {
		t.Error("IsScopedAttribute(\"eduPersonScopedAffiliation\") = false, want true")
	}
}

func TestIsScopedAttribute_Mail(t *testing.T) {
	if IsScopedAttribute("mail") {
		t.Error("IsScopedAttribute(\"mail\") = true, want false")
	}
}

func TestIsScopedAttribute_OID_EPPN(t *testing.T) {
	oid := "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
	if !IsScopedAttribute(oid) {
		t.Errorf("IsScopedAttribute(%q) = false, want true", oid)
	}
}

func TestIsScopedAttribute_OID_ScopedAffiliation(t *testing.T) {
	oid := "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"
	if !IsScopedAttribute(oid) {
		t.Errorf("IsScopedAttribute(%q) = false, want true", oid)
	}
}

func TestIsScopedAttribute_Unknown(t *testing.T) {
	if IsScopedAttribute("unknownAttribute") {
		t.Error("IsScopedAttribute(\"unknownAttribute\") = true, want false")
	}
}

func TestIsScopedAttribute_Empty(t *testing.T) {
	if IsScopedAttribute("") {
		t.Error("IsScopedAttribute(\"\") = true, want false")
	}
}

// Cycle 4: ValidateScope literal matching tests
func TestValidateScope_ExactMatch(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: "example.edu", Regexp: false},
	}
	if !ValidateScope("example.edu", allowed) {
		t.Error("ValidateScope(\"example.edu\", allowed) = false, want true")
	}
}

func TestValidateScope_NoMatch(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: "example.edu", Regexp: false},
	}
	if ValidateScope("evil.edu", allowed) {
		t.Error("ValidateScope(\"evil.edu\", allowed) = true, want false")
	}
}

func TestValidateScope_Empty(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: "example.edu", Regexp: false},
	}
	if ValidateScope("", allowed) {
		t.Error("ValidateScope(\"\", allowed) = true, want false")
	}
}

func TestValidateScope_NoAllowedScopes(t *testing.T) {
	allowed := []ScopeInfo{}
	if ValidateScope("example.edu", allowed) {
		t.Error("ValidateScope(\"example.edu\", []) = true, want false")
	}
}

func TestValidateScope_NilAllowedScopes(t *testing.T) {
	var allowed []ScopeInfo
	if ValidateScope("example.edu", allowed) {
		t.Error("ValidateScope(\"example.edu\", nil) = true, want false")
	}
}

func TestValidateScope_MultipleScopes(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: "example.edu", Regexp: false},
		{Value: "partner.edu", Regexp: false},
	}
	if !ValidateScope("example.edu", allowed) {
		t.Error("ValidateScope(\"example.edu\", allowed) = false, want true")
	}
	if !ValidateScope("partner.edu", allowed) {
		t.Error("ValidateScope(\"partner.edu\", allowed) = false, want true")
	}
	if ValidateScope("evil.edu", allowed) {
		t.Error("ValidateScope(\"evil.edu\", allowed) = true, want false")
	}
}

// Cycle 5: ValidateScope regex matching tests
func TestValidateScope_RegexMatch(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: `.*\.partner\.edu`, Regexp: true},
	}
	if !ValidateScope("sub.partner.edu", allowed) {
		t.Error("ValidateScope(\"sub.partner.edu\", allowed) = false, want true")
	}
	if !ValidateScope("anything.partner.edu", allowed) {
		t.Error("ValidateScope(\"anything.partner.edu\", allowed) = false, want true")
	}
}

func TestValidateScope_RegexNoMatch(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: `sub\.partner\.edu`, Regexp: true},
	}
	if ValidateScope("partner.edu", allowed) {
		t.Error("ValidateScope(\"partner.edu\", allowed) = true, want false")
	}
	if ValidateScope("other.partner.edu", allowed) {
		t.Error("ValidateScope(\"other.partner.edu\", allowed) = true, want false")
	}
}

func TestValidateScope_InvalidRegex(t *testing.T) {
	// Invalid regex should return false, not panic
	allowed := []ScopeInfo{
		{Value: `[invalid`, Regexp: true}, // Unclosed bracket
	}
	if ValidateScope("test", allowed) {
		t.Error("ValidateScope with invalid regex = true, want false")
	}
}

func TestValidateScope_MixedLiteralAndRegex(t *testing.T) {
	allowed := []ScopeInfo{
		{Value: "example.edu", Regexp: false},
		{Value: `.*\.partner\.edu`, Regexp: true},
	}
	if !ValidateScope("example.edu", allowed) {
		t.Error("ValidateScope(\"example.edu\", allowed) = false, want true")
	}
	if !ValidateScope("sub.partner.edu", allowed) {
		t.Error("ValidateScope(\"sub.partner.edu\", allowed) = false, want true")
	}
	if ValidateScope("evil.edu", allowed) {
		t.Error("ValidateScope(\"evil.edu\", allowed) = true, want false")
	}
}

// =============================================================================
// Property-Based Tests (Cycle 6)
// =============================================================================

// checkScopeValidationInvariants verifies security-critical invariants:
// 1. Empty scope always returns false
// 2. Empty allowed list always returns false
// 3. Exact literal match always returns true
// 4. Case-sensitive matching (no accidental case folding)
func checkScopeValidationInvariants(scope string, allowed []ScopeInfo, result bool) bool {
	// Invariant 1: Empty scope always returns false
	if scope == "" {
		return !result
	}

	// Invariant 2: Empty allowed list always returns false
	if len(allowed) == 0 {
		return !result
	}

	// Invariant 3: Exact literal match always returns true
	for _, s := range allowed {
		if !s.Regexp && scope == s.Value {
			return result
		}
	}

	// Invariant 4: Case-sensitive matching
	// If scope doesn't match exactly (case-sensitive), result should be false
	// for literal scopes
	for _, s := range allowed {
		if !s.Regexp {
			// Check if scope matches case-insensitively but not case-sensitively
			if strings.EqualFold(scope, s.Value) && scope != s.Value {
				// Case mismatch - should return false for literal match
				return !result
			}
		}
	}

	return true
}

// Cycle 6: Property-Based Test - Empty Scope Invariant
func TestValidateScope_Property_EmptyScope(t *testing.T) {
	f := func(allowed []ScopeInfo) bool {
		result := ValidateScope("", allowed)
		// Empty scope should always return false
		return !result
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 6: Property-Based Test - Empty Allowed List Invariant
func TestValidateScope_Property_EmptyAllowed(t *testing.T) {
	f := func(scope string) bool {
		// Skip empty scope (handled by other test)
		if scope == "" {
			return true
		}
		result := ValidateScope(scope, []ScopeInfo{})
		// Empty allowed list should always return false
		return !result
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 6: Property-Based Test - Literal Match Invariant
func TestValidateScope_Property_LiteralMatch(t *testing.T) {
	f := func(scope string) bool {
		// Skip empty scope
		if scope == "" {
			return true
		}

		allowed := []ScopeInfo{
			{Value: scope, Regexp: false},
		}
		result := ValidateScope(scope, allowed)
		// Exact match should always return true
		return result
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 6: Property-Based Test - Case Sensitivity Invariant
func TestValidateScope_Property_CaseSensitive(t *testing.T) {
	f := func(baseScope string) bool {
		// Skip empty scope
		if baseScope == "" {
			return true
		}

		// Create a case-variant (swap case of first letter if possible)
		var variant string
		if len(baseScope) > 0 {
			first := baseScope[0]
			if first >= 'a' && first <= 'z' {
				variant = strings.ToUpper(string(first)) + baseScope[1:]
			} else if first >= 'A' && first <= 'Z' {
				variant = strings.ToLower(string(first)) + baseScope[1:]
			} else {
				// Can't create case variant, skip
				return true
			}
		} else {
			return true
		}

		// If variant is different from baseScope, it should not match
		if variant != baseScope {
			allowed := []ScopeInfo{
				{Value: baseScope, Regexp: false},
			}
			result := ValidateScope(variant, allowed)
			// Case mismatch should return false
			return !result
		}

		return true
	}

	// Custom generator to create reasonable scope strings
	config := &quick.Config{
		Values: func(values []reflect.Value, r *rand.Rand) {
			// Generate a simple domain-like string
			parts := []string{
				randomString(r, 3, 10),
				randomString(r, 2, 4),
			}
			scope := strings.Join(parts, ".")
			values[0] = reflect.ValueOf(scope)
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}

// randomString generates a random string of length between min and max
func randomString(r *rand.Rand, minLen, maxLen int) string {
	length := minLen + r.Intn(maxLen-minLen+1)
	bytes := make([]byte, length)
	for i := range bytes {
		bytes[i] = byte('a' + r.Intn(26))
	}
	return string(bytes)
}

// Cycle 11: Property-Based Test - Full Validation Chain
func TestScopeValidation_Property_EndToEnd(t *testing.T) {
	contains := func(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	}

	f := func(username, scopePart string, allowedScopes []string) bool {
		// Skip empty inputs
		if username == "" || scopePart == "" {
			return true
		}

		// Build attribute value
		value := username + "@" + scopePart

		// Build scope config
		scopes := make([]ScopeInfo, len(allowedScopes))
		for i, s := range allowedScopes {
			scopes[i] = ScopeInfo{Value: s, Regexp: false}
		}

		// Extract and validate
		extracted := ExtractScope(value)
		result := ValidateScope(extracted, scopes)

		// Invariant: result true iff scopePart in allowedScopes
		expected := contains(allowedScopes, scopePart)
		return result == expected
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 8: IdPInfo extension tests
func TestIdPInfo_AllowedScopes_JSON(t *testing.T) {
	idp := IdPInfo{
		EntityID: "https://idp.example.com",
		AllowedScopes: []ScopeInfo{
			{Value: "example.edu", Regexp: false},
			{Value: `.*\.partner\.edu`, Regexp: true},
		},
	}

	// Verify struct can be created and scopes are accessible
	if len(idp.AllowedScopes) != 2 {
		t.Errorf("IdPInfo.AllowedScopes length = %d, want 2", len(idp.AllowedScopes))
	}

	if idp.AllowedScopes[0].Value != "example.edu" {
		t.Errorf("IdPInfo.AllowedScopes[0].Value = %q, want %q", idp.AllowedScopes[0].Value, "example.edu")
	}

	if idp.AllowedScopes[1].Regexp != true {
		t.Errorf("IdPInfo.AllowedScopes[1].Regexp = %v, want true", idp.AllowedScopes[1].Regexp)
	}
}

func TestIdPInfo_AllowedScopes_Empty(t *testing.T) {
	idp := IdPInfo{
		EntityID: "https://idp.example.com",
	}

	if idp.AllowedScopes != nil && len(idp.AllowedScopes) != 0 {
		t.Errorf("IdPInfo.AllowedScopes = %v, want nil or empty", idp.AllowedScopes)
	}
}



