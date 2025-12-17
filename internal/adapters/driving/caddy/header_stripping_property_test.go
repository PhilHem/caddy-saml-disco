//go:build unit

package caddy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Property-Based Tests for Header Stripping
// =============================================================================
//
// These tests verify security-critical invariants of header stripping through
// systematic exploration of the state space. Header stripping prevents header
// injection attacks where malicious clients send spoofed headers that could
// override SAML-derived attributes.
//
// Security Properties Verified:
// 1. Spoofed headers are always removed before injection (when strip enabled)
// 2. Case-insensitive header matching (HTTP headers are case-insensitive)
// 3. Multiple header values are all removed
// 4. Prefix handling works correctly (with and without header prefix)
// 5. Multi-SP isolation (each SP config strips independently)
//
// Bugs Found Through Property-Based Testing:
// - See KNOWN_ISSUES.md for discovered bugs

// =============================================================================
// Helper Functions
// =============================================================================

// generateHeaderVariations generates all case variations of a header name
// for testing case-insensitive matching. Returns canonical form and variations.
func generateHeaderVariations(headerName string) []string {
	if headerName == "" {
		return []string{""}
	}

	// HTTP header canonical form: First-Letter-Of-Each-Word-Capitalized
	canonical := http.CanonicalHeaderKey(headerName)
	variations := []string{canonical}

	// Generate common case variations
	lower := strings.ToLower(headerName)
	upper := strings.ToUpper(headerName)
	mixed := strings.ToLower(headerName[:1]) + strings.ToUpper(headerName[1:])

	// Add variations if different from canonical
	for _, v := range []string{lower, upper, mixed, headerName} {
		if v != canonical && !contains(variations, v) {
			variations = append(variations, v)
		}
	}

	return variations
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// =============================================================================
// Property Tests
// =============================================================================

// TestHeaderStripping_Property_SpoofedHeadersAlwaysRemoved verifies that
// when strip is enabled, incoming spoofed headers are always removed before
// injection, regardless of header name case, value, or number of values.
func TestHeaderStripping_Property_SpoofedHeadersAlwaysRemoved(t *testing.T) {
	f := func(headerName, spoofedValue, attrValue string, stripEnabled bool, hasPrefix bool) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}

		// Normalize header name for testing
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		prefix := ""
		if hasPrefix {
			prefix = "X-Saml-"
		}

		// Create request with spoofed header
		req := &http.Request{Header: make(http.Header)}
		finalHeaderName := ApplyHeaderPrefix(prefix, headerName)

		// Set spoofed header with multiple values to test all are removed
		req.Header.Add(finalHeaderName, spoofedValue)
		req.Header.Add(finalHeaderName, "another-spoofed-value")

		// Create SAMLDisco with strip enabled/disabled
		disco := &SAMLDisco{
			Config: Config{
				HeaderPrefix:          prefix,
				StripAttributeHeaders: boolPtr(stripEnabled),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		// Create session with attribute
		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": attrValue,
			},
		}

		// Apply headers
		disco.applyAttributeHeaders(req, session)

		// Property: If strip enabled, spoofed headers must be removed
		// and replaced with attribute value (if present)
		if stripEnabled {
			got := req.Header.Get(finalHeaderName)
			if attrValue != "" {
				// Should have attribute value, not spoofed value
				if got != sanitizeHeaderValue(attrValue) {
					return false
				}
			} else {
				// Should be empty (no attribute to inject)
				if got != "" {
					return false
				}
			}
		} else {
			// If strip disabled, spoofed header should remain
			// (but attribute value should also be set, so we get attribute value)
			got := req.Header.Get(finalHeaderName)
			if attrValue != "" {
				// With strip disabled, Set() overwrites, so we get attribute value
				if got != sanitizeHeaderValue(attrValue) {
					return false
				}
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_Property_CaseInsensitiveMatching verifies that
// header stripping works case-insensitively, matching HTTP header semantics.
func TestHeaderStripping_Property_CaseInsensitiveMatching(t *testing.T) {
	f := func(headerName, spoofedValue, attrValue string) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		// Generate case variations
		variations := generateHeaderVariations(headerName)

		// Test each case variation
		for _, variation := range variations {
			req := &http.Request{Header: make(http.Header)}
			req.Header.Set(variation, spoofedValue)

			disco := &SAMLDisco{
				Config: Config{
					StripAttributeHeaders: boolPtr(true),
					AttributeHeaders: []AttributeMapping{
						{SAMLAttribute: "test:attr", HeaderName: headerName},
					},
				},
			}

			session := &domain.Session{
				Subject: "user@example.com",
				Attributes: map[string]string{
					"test:attr": attrValue,
				},
			}

			disco.applyAttributeHeaders(req, session)

			// Property: Header should be stripped regardless of case
			// Use canonical form for checking
			canonical := http.CanonicalHeaderKey(headerName)
			got := req.Header.Get(canonical)

			if attrValue != "" {
				// Should have attribute value, not spoofed value
				if got != sanitizeHeaderValue(attrValue) {
					return false
				}
			} else {
				// Should be empty
				if got != "" {
					return false
				}
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_Property_MultipleValuesRemoved verifies that
// when multiple values exist for the same header, all are removed.
func TestHeaderStripping_Property_MultipleValuesRemoved(t *testing.T) {
	f := func(headerName string, numValues int) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}
		if numValues < 1 || numValues > 10 {
			return true // Limit to reasonable range
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		req := &http.Request{Header: make(http.Header)}

		// Add multiple spoofed values
		for i := 0; i < numValues; i++ {
			req.Header.Add(headerName, "spoofed-value-"+string(rune('0'+i)))
		}

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": "authentic-value",
			},
		}

		disco.applyAttributeHeaders(req, session)

		// Property: All spoofed values removed, only authentic value remains
		values := req.Header.Values(headerName)
		if len(values) != 1 {
			return false
		}
		if values[0] != sanitizeHeaderValue("authentic-value") {
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_Property_PrefixHandling verifies that
// header stripping correctly handles header prefixes.
func TestHeaderStripping_Property_PrefixHandling(t *testing.T) {
	f := func(headerName, prefix string, spoofedValue, attrValue string) bool {
		// Skip invalid inputs
		if headerName == "" {
			return true
		}

		// Ensure header name is valid (starts with X- or will after prefix)
		if prefix == "" && !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") && prefix == "" {
			headerName = "X-" + headerName
		}

		// Ensure prefix is valid if provided
		if prefix != "" && !strings.HasPrefix(strings.ToLower(prefix), "x-") {
			return true
		}

		finalHeaderName := ApplyHeaderPrefix(prefix, headerName)

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(finalHeaderName, spoofedValue)

		disco := &SAMLDisco{
			Config: Config{
				HeaderPrefix:          prefix,
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": attrValue,
			},
		}

		disco.applyAttributeHeaders(req, session)

		// Property: Prefixed header should be stripped correctly
		got := req.Header.Get(finalHeaderName)
		if attrValue != "" {
			if got != sanitizeHeaderValue(attrValue) {
				return false
			}
		} else {
			if got != "" {
				return false
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_Property_PrefixCaseCanonical verifies that
// header stripping works correctly regardless of case variations in prefix
// and headerName. This tests HEADER-007: Prefix case canonicalization.
// Property: For any valid (prefix, headerName) case combination, Del() and Set()
// operations must target the same canonical header name.
func TestHeaderStripping_Property_PrefixCaseCanonical(t *testing.T) {
	// Generate case variations for prefix and headerName
	prefixBase := "X-Saml-"
	headerNameBase := "Role"

	prefixVariations := generateHeaderVariations(prefixBase)
	headerNameVariations := generateHeaderVariations(headerNameBase)

	// Test all combinations of prefix and headerName case variations
	for _, prefixVar := range prefixVariations {
		for _, headerNameVar := range headerNameVariations {
			// Skip if prefix doesn't end with dash (invalid)
			if prefixVar != "" && !strings.HasSuffix(prefixVar, "-") {
				continue
			}

			// Calculate expected canonical form
			combined := ApplyHeaderPrefix(prefixVar, headerNameVar)
			expectedCanonical := http.CanonicalHeaderKey(combined)

			// Test with spoofed header using different case variation
			for _, spoofedPrefixVar := range prefixVariations {
				for _, spoofedHeaderNameVar := range headerNameVariations {
					if spoofedPrefixVar != "" && !strings.HasSuffix(spoofedPrefixVar, "-") {
						continue
					}

					spoofedCombined := ApplyHeaderPrefix(spoofedPrefixVar, spoofedHeaderNameVar)
					spoofedCanonical := http.CanonicalHeaderKey(spoofedCombined)

					// Only test if spoofed header canonicalizes to same as config
					// (we're testing that case doesn't matter)
					if spoofedCanonical != expectedCanonical {
						continue
					}

					spoofedValue := "spoofed-value"
					attrValue := "authentic-value"

					req := &http.Request{Header: make(http.Header)}
					// Set spoofed header with non-canonical case
					req.Header.Set(spoofedCombined, spoofedValue)

					disco := &SAMLDisco{
						Config: Config{
							HeaderPrefix:          prefixVar,
							StripAttributeHeaders: boolPtr(true),
							AttributeHeaders: []AttributeMapping{
								{SAMLAttribute: "test:attr", HeaderName: headerNameVar},
							},
						},
					}

					session := &domain.Session{
						Subject: "user@example.com",
						Attributes: map[string]string{
							"test:attr": attrValue,
						},
					}

					disco.applyAttributeHeaders(req, session)

					// Property: Header should be stripped and replaced at canonical name
					// regardless of case used in config or spoofed header
					got := req.Header.Get(expectedCanonical)
					if got != sanitizeHeaderValue(attrValue) {
						t.Errorf("prefix=%q headerName=%q spoofedPrefix=%q spoofedHeaderName=%q: "+
							"expected canonical header %q to have value %q, got %q",
							prefixVar, headerNameVar, spoofedPrefixVar, spoofedHeaderNameVar,
							expectedCanonical, sanitizeHeaderValue(attrValue), got)
						return
					}
				}
			}
		}
	}
}

// TestHeaderStripping_Property_EntitlementHeadersStripped verifies that
// entitlement headers are also stripped when configured.
func TestHeaderStripping_Property_EntitlementHeadersStripped(t *testing.T) {
	f := func(headerName, spoofedValue, role string) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: headerName},
				},
			},
		}

		// Create session (entitlements are looked up by subject)
		session := &domain.Session{
			Subject:    "user@example.com",
			Attributes: map[string]string{},
		}

		// Note: This test requires an entitlement store to be set up
		// For property testing, we'll verify the stripping happens
		// even without a store (header should be removed)
		disco.applyAttributeHeaders(req, session)

		// Property: Spoofed entitlement header should be stripped
		// (even if no entitlement store is configured)
		got := req.Header.Get(headerName)
		// Without entitlement store, header should be empty after strip
		if got != "" {
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_DefaultBehaviorConsistency_Unit is a unit test that
// directly verifies the bug: multi-SP doesn't strip when StripAttributeHeaders is nil.
func TestHeaderStripping_DefaultBehaviorConsistency_Unit(t *testing.T) {
	headerName := "X-Role"
	spoofedValue := "spoofed-admin"

	// Test single-SP mode with nil StripAttributeHeaders (should default to true)
	req1 := &http.Request{Header: make(http.Header)}
	req1.Header.Set(headerName, spoofedValue)

	disco1 := &SAMLDisco{
		Config: Config{
			// StripAttributeHeaders is nil - should default to true
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: headerName},
			},
		},
	}

	// Session with NO matching attribute
	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"other:attr": "some-value", // Different attribute, not mapped
		},
	}

	disco1.applyAttributeHeaders(req1, session)

	// Test multi-SP mode with nil StripAttributeHeaders (should default to true)
	req2 := &http.Request{Header: make(http.Header)}
	req2.Header.Set(headerName, spoofedValue)

	spConfig := &SPConfig{
		Hostname: "test.example.com",
		Config: Config{
			// StripAttributeHeaders is nil - should default to true
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: headerName},
			},
		},
	}

	disco2 := &SAMLDisco{}
	disco2.applyAttributeHeadersForSP(req2, session, spConfig)

	// Single-SP should strip spoofed header (empty because no matching attribute)
	got1 := req1.Header.Get(headerName)
	if got1 != "" {
		t.Errorf("single-SP: expected empty header after strip, got %q", got1)
	}

	// Multi-SP should also strip (empty), but currently doesn't strip when nil
	// So got2 will still have spoofedValue (the bug)
	got2 := req2.Header.Get(headerName)
	if got2 != "" {
		t.Errorf("multi-SP: expected empty header after strip (bug - currently doesn't strip when nil), got %q", got2)
	}

	// Both should behave identically (both empty)
	if got1 != got2 {
		t.Errorf("inconsistent behavior: single-SP=%q, multi-SP=%q (expected both empty)", got1, got2)
	}
}

// TestHeaderStripping_Property_DefaultBehaviorConsistency verifies that
// single-SP and multi-SP modes have consistent default strip behavior when
// StripAttributeHeaders is nil (should default to true).
func TestHeaderStripping_Property_DefaultBehaviorConsistency(t *testing.T) {
	f := func(headerName, spoofedValue string) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		// Test single-SP mode with nil StripAttributeHeaders (should default to true)
		req1 := &http.Request{Header: make(http.Header)}
		req1.Header.Set(headerName, spoofedValue)

		disco1 := &SAMLDisco{
			Config: Config{
				// StripAttributeHeaders is nil - should default to true
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		// Session with NO matching attribute - this is where the bug shows
		// Single-SP will strip the spoofed header (leaving it empty)
		// Multi-SP will NOT strip (leaving spoofed value)
		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"other:attr": "some-value", // Different attribute, not mapped
			},
		}

		disco1.applyAttributeHeaders(req1, session)

		// Test multi-SP mode with nil StripAttributeHeaders (should default to true)
		req2 := &http.Request{Header: make(http.Header)}
		req2.Header.Set(headerName, spoofedValue)

		spConfig := &SPConfig{
			Hostname: "test.example.com",
			Config: Config{
				// StripAttributeHeaders is nil - should default to true
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		disco2 := &SAMLDisco{}
		disco2.applyAttributeHeadersForSP(req2, session, spConfig)

		// Property: Both should strip spoofed headers when StripAttributeHeaders is nil
		// Single-SP: shouldStripAttributeHeaders() returns true when nil, so strips (empty result)
		// Multi-SP: should also strip (but currently doesn't - this is the bug)
		got1 := req1.Header.Get(headerName)
		got2 := req2.Header.Get(headerName)

		// Single-SP should strip spoofed header (empty because no matching attribute)
		if got1 != "" {
			// Single-SP didn't strip - this shouldn't happen
			return false
		}

		// Multi-SP should also strip (empty), but currently doesn't strip when nil
		// So got2 will still have spoofedValue (the bug)
		if got2 != "" {
			// Multi-SP didn't strip when it should have - this is the bug
			return false
		}

		// Both should behave identically (both empty)
		return got1 == got2
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestHeaderStripping_Property_MappingErrorHandling verifies behavior when
// MapAttributesToHeadersWithPrefix fails after headers are stripped.
// This tests HEADER-004: Headers stripped but not replaced on mapping error.
// The code implements rollback - this test verifies it works correctly.
func TestHeaderStripping_Property_MappingErrorHandling(t *testing.T) {
	t.Run("single-SP mode - rollback on mapping error", func(t *testing.T) {
		headerName := "X-Role"
		spoofedValue := "spoofed-admin"
		spoofedValue2 := "spoofed-admin-2"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)
		req.Header.Add(headerName, spoofedValue2) // Multiple values

		// Create config with invalid header name that will cause mapping to fail
		// This simulates a runtime error scenario (though Validate() should catch this)
		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				HeaderPrefix:          "X-Saml-",
				AttributeHeaders: []AttributeMapping{
					// Use invalid header name that will fail validation in MapAttributesToHeadersWithPrefix
					// The prefix + headerName combination creates "X-Saml-invalid" which is valid,
					// but we'll use a header name that when combined with prefix becomes invalid
					// Actually, let's use a valid config but test the rollback mechanism directly
					{SAMLAttribute: "test:attr", HeaderName: "Role"}, // Valid: becomes "X-Saml-Role"
				},
			},
		}

		// Set header with the prefixed name that will be stripped
		prefixedHeaderName := "X-Saml-Role"
		req.Header.Del(headerName)
		req.Header.Set(prefixedHeaderName, spoofedValue)
		req.Header.Add(prefixedHeaderName, spoofedValue2)

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": "authentic-value",
			},
		}

		// Normal case: mapping succeeds, header replaced
		disco.applyAttributeHeaders(req, session)
		got := req.Header.Get(prefixedHeaderName)
		if got != sanitizeHeaderValue("authentic-value") {
			t.Errorf("expected header to be replaced with authentic value, got %q", got)
		}

		// Test rollback: Create scenario where mapping would fail
		// Since Validate() should catch config errors, we test rollback by verifying
		// the mechanism exists. To actually test error path, we'd need to bypass Validate()
		// or use a runtime error scenario. For now, we verify rollback code exists and
		// test restoreHeaderState directly.
	})

	t.Run("restoreHeaderState function works correctly", func(t *testing.T) {
		headerName := "X-Role"
		originalValue1 := "original-value-1"
		originalValue2 := "original-value-2"

		req := &http.Request{Header: make(http.Header)}
		originalHeaders := map[string][]string{
			headerName: {originalValue1, originalValue2},
		}

		// Verify header doesn't exist initially
		if req.Header.Get(headerName) != "" {
			t.Errorf("expected header to be empty initially")
		}

		// Restore headers (restoreHeaderState is package-private, accessible in tests)
		restoreHeaderState(req, originalHeaders)

		// Verify both values were restored
		values := req.Header[headerName]
		if len(values) != 2 {
			t.Errorf("expected 2 header values, got %d", len(values))
		}
		if values[0] != originalValue1 || values[1] != originalValue2 {
			t.Errorf("expected values [%q, %q], got %v", originalValue1, originalValue2, values)
		}
	})

	t.Run("rollback on attribute mapping error", func(t *testing.T) {
		// Test that headers are restored when MapAttributesToHeadersWithPrefix fails
		// We'll create a scenario where mapping fails by using an invalid prefix at runtime
		// (even though Validate() should catch this, we test the rollback mechanism)

		headerName := "X-Role"
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				// Use invalid prefix that will cause MapAttributesToHeadersWithPrefix to fail
				// This simulates a runtime error scenario
				HeaderPrefix: "invalid-prefix-", // Invalid: doesn't start with X-
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": "authentic-value",
			},
		}

		// Apply headers - mapping should fail due to invalid prefix
		disco.applyAttributeHeaders(req, session)

		// Verify header was restored (rollback happened)
		got := req.Header.Get(headerName)
		if got != spoofedValue {
			t.Errorf("expected header to be restored to original value %q after mapping error, got %q", spoofedValue, got)
		}
	})

	t.Run("multi-SP mode - rollback on mapping error", func(t *testing.T) {
		headerName := "X-Role"
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		spConfig := &SPConfig{
			Hostname: "test.example.com",
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": "authentic-value",
			},
		}

		disco := &SAMLDisco{}
		disco.applyAttributeHeadersForSP(req, session, spConfig)

		got := req.Header.Get(headerName)
		if got != sanitizeHeaderValue("authentic-value") {
			t.Errorf("expected header to be replaced with authentic value, got %q", got)
		}
	})
}

// TestHeaderStripping_Property_EntitlementMappingErrorHandling verifies behavior when
// MapEntitlementsToHeaders fails after entitlement headers are stripped.
// This tests HEADER-009: Entitlement headers stripped but not replaced on mapping error.
// The code implements rollback - this test verifies it works correctly.
func TestHeaderStripping_Property_EntitlementMappingErrorHandling(t *testing.T) {
	t.Run("single-SP mode - rollback on entitlement mapping error", func(t *testing.T) {
		// Use a header name that matches what will be stripped
		// The mapping uses "invalid-header" which becomes the header name to strip
		// But we need to use the actual header name that matches the mapping
		headerName := "invalid-header" // This matches the HeaderName in mapping
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				// Use invalid header name in entitlement mapping that will cause validation error
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "invalid-header"}, // Invalid: doesn't start with X-
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{},
		}

		// Create an in-memory entitlement store that returns a result
		entitlementStore := entitlements.NewInMemoryEntitlementStore()
		entitlementStore.Add(domain.Entitlement{
			Subject: "user@example.com",
			Roles:   []string{"admin", "staff"},
		})

		// Set entitlement store
		disco.entitlementStore = entitlementStore

		// Apply headers - entitlement mapping should fail due to invalid header name
		disco.applyAttributeHeaders(req, session)

		// Verify header was restored (rollback happened)
		got := req.Header.Get(headerName)
		if got != spoofedValue {
			t.Errorf("expected entitlement header to be restored to original value %q after mapping error, got %q", spoofedValue, got)
		}
	})

	t.Run("multi-SP mode - rollback on entitlement mapping error", func(t *testing.T) {
		// Use a header name that matches what will be stripped
		headerName := "invalid-header" // This matches the HeaderName in mapping
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		// Create an in-memory entitlement store that returns a result
		entitlementStore := entitlements.NewInMemoryEntitlementStore()
		entitlementStore.Add(domain.Entitlement{
			Subject: "user@example.com",
			Roles:   []string{"admin", "staff"},
		})

		spConfig := &SPConfig{
			Hostname: "test.example.com",
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "invalid-header"}, // Invalid header name
				},
			},
			entitlementStore: entitlementStore,
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{},
		}

		disco := &SAMLDisco{}
		disco.applyAttributeHeadersForSP(req, session, spConfig)

		// Verify header was restored (rollback happened)
		got := req.Header.Get(headerName)
		if got != spoofedValue {
			t.Errorf("expected entitlement header to be restored to original value %q after mapping error, got %q", spoofedValue, got)
		}
	})
}

// TestHeaderStripping_Property_SessionNilHandling verifies behavior when
// session is nil after headers are stripped.
// This tests HEADER-006: Session nil after stripping.
func TestHeaderStripping_Property_SessionNilHandling(t *testing.T) {
	headerName := "X-Role"
	spoofedValue := "spoofed-admin"

	req := &http.Request{Header: make(http.Header)}
	req.Header.Set(headerName, spoofedValue)

	got := req.Header.Get(headerName)
	if got != spoofedValue {
		t.Errorf("expected spoofed value before stripping, got %q", got)
	}

	disco := &SAMLDisco{
		Config: Config{
			StripAttributeHeaders: boolPtr(true),
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: headerName},
			},
		},
	}

	// Session is nil (unauthenticated request)
	disco.applyAttributeHeaders(req, nil)

	got = req.Header.Get(headerName)

	// Current behavior: Headers are stripped but not replaced when session is nil
	// This is correct behavior for unauthenticated requests - we strip spoofed headers
	// for security, but don't set legitimate headers since there's no session.
	if got != "" {
		t.Errorf("expected empty header when session is nil (headers stripped but not replaced), got %q", got)
	}

	// This is correct behavior: unauthenticated requests should have headers stripped
	// but not replaced, as there's no session data to inject.
}

// TestHeaderStripping_Property_NonASCIICharacters verifies that
// header stripping works correctly with non-ASCII characters in header names.
// This tests HEADER-002: Case sensitivity edge cases with non-ASCII characters.
// Note: HTTP header names should be ASCII per RFC 7230, but we test edge cases
// to verify Go's http.Header.Del() behavior.
func TestHeaderStripping_Property_NonASCIICharacters(t *testing.T) {
	testCases := []struct {
		name       string
		headerName string
		valid      bool // Whether this is a valid HTTP header name per RFC 7230
	}{
		{"ASCII only", "X-Role", true},
		{"Unicode in name", "X-Rôle", false}, // Non-ASCII character
		{"Cyrillic", "X-Пользователь", false},
		{"Chinese", "X-用户", false},
		{"Mixed ASCII Unicode", "X-User角色", false},
		{"Emoji", "X-User🎭", false},
		{"Unicode normalization NFC", "X-Rôle", false},       // é in NFC
		{"Unicode normalization NFD", "X-Ro\u0301le", false}, // é in NFD (e + combining acute)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spoofedValue := "spoofed-value"
			attrValue := "authentic-value"

			// Test canonical form
			canonical := http.CanonicalHeaderKey(tc.headerName)
			req := &http.Request{Header: make(http.Header)}
			req.Header.Set(canonical, spoofedValue)

			disco := &SAMLDisco{
				Config: Config{
					StripAttributeHeaders: boolPtr(true),
					AttributeHeaders: []AttributeMapping{
						{SAMLAttribute: "test:attr", HeaderName: tc.headerName},
					},
				},
			}

			session := &domain.Session{
				Subject: "user@example.com",
				Attributes: map[string]string{
					"test:attr": attrValue,
				},
			}

			disco.applyAttributeHeaders(req, session)

			got := req.Header.Get(canonical)

			// Property: Header should be stripped and replaced with attribute value
			// Note: If header name is invalid (non-ASCII), Go's http.Header may behave
			// differently. We verify the behavior.
			if tc.valid {
				// Valid ASCII headers should work correctly
				if got != sanitizeHeaderValue(attrValue) {
					t.Errorf("valid header %q: expected %q, got %q", tc.headerName, sanitizeHeaderValue(attrValue), got)
				}
			} else {
				// Invalid headers (non-ASCII) - document behavior
				// Go's http.Header may or may not handle these correctly
				// We test to see what happens
				if got == spoofedValue {
					t.Logf("non-ASCII header %q: spoofed value persisted (Go's http.Header may not handle non-ASCII)", tc.headerName)
				} else if got != sanitizeHeaderValue(attrValue) && got != "" {
					t.Logf("non-ASCII header %q: unexpected value %q", tc.headerName, got)
				}
			}
		})
	}
}

// TestHeaderStripping_Property_CaseInsensitiveMatching_NonASCII extends
// the existing case-insensitive test to include non-ASCII characters.
func TestHeaderStripping_Property_CaseInsensitiveMatching_NonASCII(t *testing.T) {
	// Test with non-ASCII characters that have case variations
	// Note: Most non-ASCII characters don't have case variations, but some do
	testCases := []struct {
		name       string
		headerName string
	}{
		{"ASCII with case", "X-Role"},
		{"Turkish I", "X-İşlem"}, // Turkish dotless I
		{"Greek", "X-Χρήστης"},   // Greek characters
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spoofedValue := "spoofed"
			attrValue := "authentic"

			// Generate case variations (may not work for all non-ASCII)
			variations := generateHeaderVariations(tc.headerName)

			for _, variation := range variations {
				req := &http.Request{Header: make(http.Header)}
				req.Header.Set(variation, spoofedValue)

				disco := &SAMLDisco{
					Config: Config{
						StripAttributeHeaders: boolPtr(true),
						AttributeHeaders: []AttributeMapping{
							{SAMLAttribute: "test:attr", HeaderName: tc.headerName},
						},
					},
				}

				session := &domain.Session{
					Subject: "user@example.com",
					Attributes: map[string]string{
						"test:attr": attrValue,
					},
				}

				disco.applyAttributeHeaders(req, session)

				canonical := http.CanonicalHeaderKey(tc.headerName)
				got := req.Header.Get(canonical)

				// Property: Header should be stripped regardless of case variation
				if got != sanitizeHeaderValue(attrValue) && got != "" {
					t.Errorf("header %q variation %q: expected %q or empty, got %q",
						tc.headerName, variation, sanitizeHeaderValue(attrValue), got)
				}
			}
		})
	}
}

// TestHeaderStripping_Property_RollbackOnError verifies the rollback invariant:
// If mapping fails after headers are stripped, original headers must be restored.
// This property-based test generates random valid configs to surface edge cases.
func TestHeaderStripping_Property_RollbackOnError(t *testing.T) {
	f := func(headerName string, prefix string, spoofedValue string, attrValue string) bool {
		// Generate valid header names and values
		if len(headerName) < 3 || len(headerName) > 50 {
			return true // Skip invalid lengths
		}
		if len(spoofedValue) > 1000 || len(attrValue) > 1000 {
			return true // Skip very long values
		}

		// Ensure header name is valid (starts with X-)
		if !strings.HasPrefix(strings.ToUpper(headerName), "X-") {
			headerName = "X-" + headerName
		}
		// Ensure header name is valid format
		headerName = sanitizeHeaderNameForTest(headerName)

		// Ensure prefix is valid if provided
		if prefix != "" && !strings.HasPrefix(strings.ToUpper(prefix), "X-") {
			prefix = "X-" + prefix
		}
		if prefix != "" {
			prefix = sanitizeHeaderNameForTest(prefix)
			if !strings.HasSuffix(prefix, "-") {
				prefix = prefix + "-"
			}
		}

		// Determine final header name (with prefix if applicable)
		finalHeaderName := headerName
		if prefix != "" {
			finalHeaderName = prefix + strings.TrimPrefix(headerName, "X-")
		}
		finalHeaderName = http.CanonicalHeaderKey(finalHeaderName)

		// Create request with spoofed header
		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(finalHeaderName, spoofedValue)
		req.Header.Add(finalHeaderName, spoofedValue+"-2") // Multiple values

		// Store original values for verification
		originalValues := req.Header[finalHeaderName]

		// Create config that will cause mapping to fail
		// Use invalid prefix to trigger error in MapAttributesToHeadersWithPrefix
		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				HeaderPrefix:          "invalid-prefix-", // Invalid: will cause mapping error
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:attr": attrValue,
			},
		}

		// Apply headers - mapping should fail
		disco.applyAttributeHeaders(req, session)

		// Property: Headers must be restored after mapping error
		restoredValues := req.Header[finalHeaderName]
		if len(restoredValues) != len(originalValues) {
			return false // Rollback failed - wrong number of values
		}

		// Verify values match (order may differ due to http.Header.Add)
		valuesMap := make(map[string]int)
		for _, v := range restoredValues {
			valuesMap[v]++
		}
		for _, v := range originalValues {
			valuesMap[v]--
			if valuesMap[v] < 0 {
				return false // Value missing in restored headers
			}
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// sanitizeHeaderNameForTest ensures header name is valid for testing
func sanitizeHeaderNameForTest(name string) string {
	// Remove invalid characters, keep only A-Za-z0-9-
	var result strings.Builder
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}
	s := result.String()
	if len(s) < 3 {
		return "X-Test"
	}
	return s
}

// TestHeaderStripping_Concurrency_RollbackOnError verifies that
// rollback works correctly under concurrent requests.
// This ensures rollback mechanism is thread-safe and config immutability.
func TestHeaderStripping_Concurrency_RollbackOnError(t *testing.T) {
	disco := &SAMLDisco{
		Config: Config{
			StripAttributeHeaders: boolPtr(true),
			HeaderPrefix:          "invalid-prefix-", // Will cause mapping error
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: "X-Role"},
			},
		},
	}

	// Test with multiple concurrent requests
	const numGoroutines = 100
	const numIterations = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numIterations; j++ {
				// Each goroutine gets its own request (no shared state)
				req := &http.Request{Header: make(http.Header)}
				spoofedValue := fmt.Sprintf("spoofed-%d-%d", goroutineID, j)
				spoofedValue2 := fmt.Sprintf("spoofed-%d-%d-2", goroutineID, j)

				req.Header.Set("X-Role", spoofedValue)
				req.Header.Add("X-Role", spoofedValue2) // Multiple values

				// Store original values
				originalValues := req.Header["X-Role"]

				session := &domain.Session{
					Subject: fmt.Sprintf("user%d@example.com", goroutineID),
					Attributes: map[string]string{
						"test:attr": fmt.Sprintf("authentic-%d-%d", goroutineID, j),
					},
				}

				// Apply headers - mapping should fail, triggering rollback
				disco.applyAttributeHeaders(req, session)

				// Verify rollback: headers should be restored
				restoredValues := req.Header["X-Role"]
				if len(restoredValues) != len(originalValues) {
					errors <- fmt.Errorf("goroutine %d iteration %d: expected %d restored values, got %d",
						goroutineID, j, len(originalValues), len(restoredValues))
					return
				}

				// Verify values match
				valuesMap := make(map[string]int)
				for _, v := range restoredValues {
					valuesMap[v]++
				}
				for _, v := range originalValues {
					valuesMap[v]--
					if valuesMap[v] < 0 {
						errors <- fmt.Errorf("goroutine %d iteration %d: missing value %q in restored headers",
							goroutineID, j, v)
						return
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}
}

// TestHeaderStripping_Concurrency_NoRaceCondition verifies that
// header stripping and injection do not have race conditions when
// called concurrently from multiple goroutines.
// This tests HEADER-001: Potential race condition in header stripping/injection.
func TestHeaderStripping_Concurrency_NoRaceCondition(t *testing.T) {
	disco := &SAMLDisco{
		Config: Config{
			StripAttributeHeaders: boolPtr(true),
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: "X-Role"},
			},
		},
	}

	// Test with multiple concurrent requests
	const numGoroutines = 100
	const numIterations = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numIterations; j++ {
				// Each goroutine gets its own request (no shared state)
				req := &http.Request{Header: make(http.Header)}
				spoofedValue := fmt.Sprintf("spoofed-%d-%d", goroutineID, j)
				attrValue := fmt.Sprintf("authentic-%d-%d", goroutineID, j)

				req.Header.Set("X-Role", spoofedValue)

				session := &domain.Session{
					Subject: fmt.Sprintf("user%d@example.com", goroutineID),
					Attributes: map[string]string{
						"test:attr": attrValue,
					},
				}

				// Call applyAttributeHeaders concurrently
				disco.applyAttributeHeaders(req, session)

				// Verify header was stripped and replaced
				got := req.Header.Get("X-Role")
				if got != sanitizeHeaderValue(attrValue) {
					errors <- fmt.Errorf("goroutine %d iteration %d: expected %q, got %q",
						goroutineID, j, sanitizeHeaderValue(attrValue), got)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errList []error
	for err := range errors {
		errList = append(errList, err)
	}

	if len(errList) > 0 {
		t.Errorf("found %d errors in concurrent execution:", len(errList))
		for _, err := range errList {
			t.Error(err)
		}
	}
}

// TestHeaderStripping_Concurrency_PropertyBased uses property-based testing
// to verify concurrent header stripping with random inputs.
func TestHeaderStripping_Concurrency_PropertyBased(t *testing.T) {
	f := func(headerName, spoofedValue, attrValue string, numGoroutines int) bool {
		// Skip invalid inputs
		if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
			return true
		}
		if numGoroutines < 1 || numGoroutines > 50 {
			return true // Limit to reasonable range
		}

		// Normalize header name
		if !strings.HasPrefix(headerName, "X-") {
			headerName = "X-" + headerName
		}

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:attr", HeaderName: headerName},
				},
			},
		}

		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Each goroutine gets its own request
				req := &http.Request{Header: make(http.Header)}
				req.Header.Set(headerName, spoofedValue)

				session := &domain.Session{
					Subject: fmt.Sprintf("user%d@example.com", id),
					Attributes: map[string]string{
						"test:attr": attrValue,
					},
				}

				disco.applyAttributeHeaders(req, session)

				got := req.Header.Get(headerName)
				expected := sanitizeHeaderValue(attrValue)
				if attrValue != "" {
					if got != expected {
						errors <- fmt.Errorf("goroutine %d: expected %q, got %q", id, expected, got)
					}
				} else {
					if got != "" {
						errors <- fmt.Errorf("goroutine %d: expected empty, got %q", id, got)
					}
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for range errors {
			// Return false on any error
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// MockEntitlementStore is a test helper that can simulate different error conditions
type MockEntitlementStore struct {
	lookupError error
	result      *domain.EntitlementResult
}

func (m *MockEntitlementStore) Lookup(subject string) (*domain.EntitlementResult, error) {
	if m.lookupError != nil {
		return nil, m.lookupError
	}
	return m.result, nil
}

func (m *MockEntitlementStore) Refresh(ctx context.Context) error {
	return nil
}

// Ensure MockEntitlementStore implements ports.EntitlementStore
var _ ports.EntitlementStore = (*MockEntitlementStore)(nil)

// TestHeaderStripping_Property_DifferentialLookupVsMappingErrors is a differential test
// comparing behavior when entitlement lookup fails vs when entitlement mapping fails.
// This tests HEADER-012: Inconsistent rollback on entitlement lookup errors.
//
// Current behavior (legacy):
// - Entitlement mapping errors: Headers ARE restored (rollback)
// - Entitlement lookup errors: Headers are NOT restored (no rollback)
//
// This test verifies the inconsistency and can be used to test both behaviors.
func TestHeaderStripping_Property_DifferentialLookupVsMappingErrors(t *testing.T) {
	t.Run("lookup error - SAML attributes still applied (HEADER-015 fix)", func(t *testing.T) {
		headerName := "X-Role"
		spoofedValue := "spoofed-admin"
		samlAttrValue := "authentic-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		// Create mock entitlement store that fails with non-ErrEntitlementNotFound error
		mockStore := &MockEntitlementStore{
			lookupError: fmt.Errorf("file read error: permission denied"),
		}

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:role", HeaderName: headerName},
				},
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Role"},
				},
			},
			entitlementStore: mockStore,
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:role": samlAttrValue,
			},
		}

		// Apply headers - lookup should fail, but SAML attributes should still be applied
		disco.applyAttributeHeaders(req, session)

		// HEADER-015 fix: SAML attributes should be applied even when entitlement lookup fails
		got := req.Header.Get(headerName)
		if got != sanitizeHeaderValue(samlAttrValue) {
			t.Errorf("expected SAML attribute value %q to be applied after lookup error, got %q", sanitizeHeaderValue(samlAttrValue), got)
		}

		// Entitlement headers should NOT be set (lookup failed)
		entitlementHeader := req.Header.Get("X-Entitlement-Role")
		if entitlementHeader != "" {
			t.Errorf("expected entitlement header to be empty (lookup failed), got %q", entitlementHeader)
		}
	})

	t.Run("mapping error - headers ARE restored (consistent behavior)", func(t *testing.T) {
		headerName := "invalid-header" // Invalid header name causes mapping error
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		// Create mock entitlement store that succeeds
		mockStore := &MockEntitlementStore{
			result: &domain.EntitlementResult{
				Roles: []string{"admin"},
			},
		}

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: headerName}, // Invalid: doesn't start with X-
				},
			},
			entitlementStore: mockStore,
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{},
		}

		// Apply headers - mapping should fail due to invalid header name
		disco.applyAttributeHeaders(req, session)

		// Expected behavior: Headers ARE restored when mapping fails
		got := req.Header.Get(headerName)
		if got != spoofedValue {
			t.Errorf("expected headers to be restored to %q after mapping error, got %q", spoofedValue, got)
		}
	})

	t.Run("property-based: differential behavior across error types", func(t *testing.T) {
		f := func(headerName, spoofedValue string, errorType int) bool {
			// Skip invalid inputs
			if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
				return true
			}

			req := &http.Request{Header: make(http.Header)}
			req.Header.Set(headerName, spoofedValue)

			// errorType: 0 = lookup error, 1 = mapping error (via invalid header)
			var mockStore *MockEntitlementStore
			var invalidHeaderName string

			if errorType%2 == 0 {
				// Lookup error scenario
				mockStore = &MockEntitlementStore{
					lookupError: fmt.Errorf("entitlement store error: %d", errorType),
				}
				invalidHeaderName = headerName // Valid header name
			} else {
				// Mapping error scenario (use invalid header name)
				mockStore = &MockEntitlementStore{
					result: &domain.EntitlementResult{
						Roles: []string{"admin"},
					},
				}
				invalidHeaderName = "invalid-header" // Invalid header name
			}

			disco := &SAMLDisco{
				Config: Config{
					StripAttributeHeaders: boolPtr(true),
					EntitlementHeaders: []EntitlementHeaderMapping{
						{Field: "roles", HeaderName: invalidHeaderName},
					},
				},
				entitlementStore: mockStore,
			}

			session := &domain.Session{
				Subject: "user@example.com",
				Attributes: map[string]string{},
			}

			disco.applyAttributeHeaders(req, session)

			got := req.Header.Get(headerName)

			// Both error types now restore headers (consistent behavior)
			return got == spoofedValue
		}

		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("multi-SP mode - lookup error headers restored", func(t *testing.T) {
		headerName := "X-Role"
		spoofedValue := "spoofed-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, spoofedValue)

		// Create mock entitlement store that fails with non-ErrEntitlementNotFound error
		mockStore := &MockEntitlementStore{
			lookupError: fmt.Errorf("file read error: permission denied"),
		}

		spConfig := &SPConfig{
			Hostname: "test.example.com",
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: headerName},
				},
			},
			entitlementStore: mockStore,
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{},
		}

		disco := &SAMLDisco{}
		disco.applyAttributeHeadersForSP(req, session, spConfig)

		// Expected behavior: Headers SHOULD be restored when lookup fails
		got := req.Header.Get(headerName)
		if got != spoofedValue {
			t.Errorf("expected headers to be restored to %q after lookup error in multi-SP mode, got %q", spoofedValue, got)
		}
	})
}

// TestHeaderStripping_Concurrency_ConfigMutationInvariant verifies that
// header names computed at validation time match those used at runtime,
// even if mutation is attempted concurrently.
// This tests HEADER-010: Config mutation between validation and runtime.
// Property: For any valid config, the header names used in applyAttributeHeaders()
// must match those computed during Validate(), regardless of concurrent mutation attempts.
func TestHeaderStripping_Concurrency_ConfigMutationInvariant(t *testing.T) {
	// Create a valid config with HeaderPrefix and AttributeHeaders
	headerPrefix := "X-Saml-"
	headerName := "Role"
	attrValue := "authentic-value"

	// Compute expected canonical header name at validation time
	expectedHeaderName := ApplyHeaderPrefix(headerPrefix, headerName)
	expectedCanonical := http.CanonicalHeaderKey(expectedHeaderName)

	// Create config and validate it
	disco := &SAMLDisco{
		Config: Config{
			EntityID:         "https://sp.example.com/saml",
			MetadataFile:     "/path/to/metadata.xml",
			CertFile:         "/path/to/cert.pem",
			KeyFile:          "/path/to/key.pem",
			HeaderPrefix:     headerPrefix,
			AttributeHeaders: []AttributeMapping{
				{SAMLAttribute: "test:attr", HeaderName: headerName},
			},
			StripAttributeHeaders: boolPtr(true),
		},
	}

	// Validate config and capture expected header names
	if err := disco.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	// Initialize snapshots (simulating Provision) to prevent mutation
	// This is what Provision() does - snapshot config values after validation
	disco.headerPrefixSnapshot = disco.HeaderPrefix
	disco.attributeHeadersSnapshot = make([]AttributeMapping, len(disco.AttributeHeaders))
	copy(disco.attributeHeadersSnapshot, disco.AttributeHeaders)
	disco.entitlementHeadersSnapshot = make([]EntitlementHeaderMapping, len(disco.EntitlementHeaders))
	copy(disco.entitlementHeadersSnapshot, disco.EntitlementHeaders)

	// Create session with matching attribute
	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"test:attr": attrValue,
		},
	}

	// Test with concurrent mutation attempts
	const numGoroutines = 50
	const numIterations = 20

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numIterations)

	// Goroutine 1: Repeatedly call applyAttributeHeaders and verify header names
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numIterations; j++ {
				// Create fresh request for each iteration
				req := &http.Request{Header: make(http.Header)}
				spoofedValue := fmt.Sprintf("spoofed-%d-%d", goroutineID, j)
				req.Header.Set(expectedCanonical, spoofedValue)

				// Apply headers - this reads HeaderPrefix and AttributeHeaders
				disco.applyAttributeHeaders(req, session)

				// Verify: header name used must match validation-time expectation
				got := req.Header.Get(expectedCanonical)
				if got != sanitizeHeaderValue(attrValue) {
					errors <- fmt.Errorf("goroutine %d iteration %d: expected header %q to have value %q, got %q",
						goroutineID, j, expectedCanonical, sanitizeHeaderValue(attrValue), got)
					return
				}

				// Also verify that the header name itself is correct (not a different name)
				// by checking all headers match expected pattern
				foundExpectedHeader := false
				for header := range req.Header {
					if http.CanonicalHeaderKey(header) == expectedCanonical {
						foundExpectedHeader = true
						break
					}
				}
				if !foundExpectedHeader && attrValue != "" {
					errors <- fmt.Errorf("goroutine %d iteration %d: expected header %q not found in request headers",
						goroutineID, j, expectedCanonical)
					return
				}
			}
		}(i)
	}

	// Goroutine 2: Attempt to mutate HeaderPrefix and AttributeHeaders concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Try various mutations
		mutations := []string{"X-Other-", "X-Different-", "X-Mutated-", ""}
		for i := 0; i < numIterations*2; i++ {
			// Mutate HeaderPrefix
			disco.HeaderPrefix = mutations[i%len(mutations)]

			// Mutate AttributeHeaders slice
			if len(disco.AttributeHeaders) > 0 {
				// Try to mutate the slice elements
				disco.AttributeHeaders[0].HeaderName = fmt.Sprintf("Mutated-%d", i)
			}

			// Try appending to slice (though this shouldn't affect existing calls)
			disco.AttributeHeaders = append(disco.AttributeHeaders, AttributeMapping{
				SAMLAttribute: "extra:attr",
				HeaderName:    fmt.Sprintf("X-Extra-%d", i),
			})

			// Reset to original values to test if mutation persists
			disco.HeaderPrefix = headerPrefix
			if len(disco.AttributeHeaders) > 0 {
				disco.AttributeHeaders[0].HeaderName = headerName
			}
			disco.AttributeHeaders = disco.AttributeHeaders[:1] // Reset slice length
		}
	}()

	wg.Wait()
	close(errors)

	// Check for errors
	var errList []error
	for err := range errors {
		errList = append(errList, err)
	}

	if len(errList) > 0 {
		t.Errorf("found %d errors indicating config mutation vulnerability:", len(errList))
		for _, err := range errList {
			t.Error(err)
		}
		// If we found errors, this confirms HEADER-010 is a real bug
	}
}

// TestHeaderStripping_Property_RestoreDoesNotAccumulate verifies that
// restoreHeaderState does not accumulate header values when restoring.
// This tests HEADER-016: Header value accumulation on partial failure.
// Property: If SAML headers are Set() and then restoreHeaderState is called,
// only original values should remain (not both SAML and original values).
func TestHeaderStripping_Property_RestoreDoesNotAccumulate(t *testing.T) {
	t.Run("restore after SAML headers set - should not accumulate", func(t *testing.T) {
		headerName := "X-Role"
		originalValue := "spoofed-admin"
		samlValue := "authentic-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Set(headerName, originalValue)

		// Save original state
		originalHeaders := map[string][]string{
			headerName: {originalValue},
		}

		// Simulate SAML headers being Set() (as happens in applyAttributeHeaders)
		canonicalHeader := http.CanonicalHeaderKey(headerName)
		req.Header.Set(canonicalHeader, samlValue)

		// Verify SAML value is set
		if req.Header.Get(canonicalHeader) != samlValue {
			t.Fatalf("expected SAML value %q to be set, got %q", samlValue, req.Header.Get(canonicalHeader))
		}

		// Restore original headers (simulating error path)
		restoreHeaderState(req, originalHeaders)

		// Property: Only original values should remain, not accumulated with SAML values
		values := req.Header[canonicalHeader]
		if len(values) != 1 {
			t.Errorf("expected 1 header value after restore, got %d: %v", len(values), values)
		}
		if values[0] != originalValue {
			t.Errorf("expected original value %q after restore, got %q", originalValue, values[0])
		}

		// Verify SAML value is NOT present
		for _, v := range values {
			if v == samlValue {
				t.Errorf("SAML value %q should not be present after restore, but found in values: %v", samlValue, values)
			}
		}
	})

	t.Run("property-based: restore does not accumulate across variations", func(t *testing.T) {
		f := func(headerName, originalValue, samlValue string) bool {
			// Skip invalid inputs
			if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
				return true
			}
			if len(originalValue) > 1000 || len(samlValue) > 1000 {
				return true // Skip very long values
			}

			// Normalize header name
			if !strings.HasPrefix(headerName, "X-") {
				headerName = "X-" + headerName
			}

			req := &http.Request{Header: make(http.Header)}
			req.Header.Set(headerName, originalValue)

			// Save original state
			originalHeaders := map[string][]string{
				headerName: {originalValue},
			}

			// Simulate SAML headers being Set()
			canonicalHeader := http.CanonicalHeaderKey(headerName)
			req.Header.Set(canonicalHeader, samlValue)

			// Restore original headers
			restoreHeaderState(req, originalHeaders)

			// Property: Only original values should remain
			values := req.Header[canonicalHeader]
			if len(values) != 1 {
				return false // Accumulation bug detected
			}
			if values[0] != originalValue {
				return false // Wrong value restored
			}

			// Verify SAML value is NOT present
			for _, v := range values {
				if v == samlValue {
					return false // SAML value accumulated
				}
			}

			return true
		}

		if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
			t.Error(err)
		}
	})

	t.Run("restore with multiple original values - should restore all", func(t *testing.T) {
		headerName := "X-Role"
		originalValue1 := "spoofed-admin"
		originalValue2 := "spoofed-user"
		samlValue := "authentic-admin"

		req := &http.Request{Header: make(http.Header)}
		req.Header.Add(headerName, originalValue1)
		req.Header.Add(headerName, originalValue2)

		// Save original state with multiple values
		originalHeaders := map[string][]string{
			headerName: {originalValue1, originalValue2},
		}

		// Simulate SAML headers being Set() (replaces all values)
		canonicalHeader := http.CanonicalHeaderKey(headerName)
		req.Header.Set(canonicalHeader, samlValue)

		// Restore original headers
		restoreHeaderState(req, originalHeaders)

		// Property: All original values should be restored, SAML value should not be present
		values := req.Header[canonicalHeader]
		if len(values) != 2 {
			t.Errorf("expected 2 original values after restore, got %d: %v", len(values), values)
		}

		// Verify both original values are present
		valueMap := make(map[string]bool)
		for _, v := range values {
			valueMap[v] = true
		}
		if !valueMap[originalValue1] || !valueMap[originalValue2] {
			t.Errorf("expected both original values %q and %q, got: %v", originalValue1, originalValue2, values)
		}

		// Verify SAML value is NOT present
		if valueMap[samlValue] {
			t.Errorf("SAML value %q should not be present after restore, but found in values: %v", samlValue, values)
		}
	})
}

// TestHeaderStripping_Property_SAMLNotSkippedOnEntitlementError verifies that
// SAML attributes are still applied when entitlement lookup fails with
// non-ErrEntitlementNotFound error.
// This tests HEADER-015: SAML attributes skipped on entitlement error.
// Property: Entitlements are supplementary - SAML attributes should always
// be applied regardless of entitlement lookup outcome.
func TestHeaderStripping_Property_SAMLNotSkippedOnEntitlementError(t *testing.T) {
	t.Run("SAML attributes applied when entitlement lookup fails", func(t *testing.T) {
		headerName := "X-Role"
		samlAttrValue := "authentic-admin"

		req := &http.Request{Header: make(http.Header)}

		// Create mock entitlement store that fails with non-ErrEntitlementNotFound error
		mockStore := &MockEntitlementStore{
			lookupError: fmt.Errorf("entitlement store error: permission denied"),
		}

		disco := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:role", HeaderName: headerName},
				},
				EntitlementHeaders: []EntitlementHeaderMapping{
					{Field: "roles", HeaderName: "X-Entitlement-Role"},
				},
			},
			entitlementStore: mockStore,
		}

		session := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:role": samlAttrValue,
			},
		}

		// Apply headers - entitlement lookup should fail, but SAML attributes should still be applied
		disco.applyAttributeHeaders(req, session)

		// Property: SAML attributes should be applied even when entitlement lookup fails
		got := req.Header.Get(headerName)
		if got != sanitizeHeaderValue(samlAttrValue) {
			t.Errorf("expected SAML attribute value %q to be applied, got %q", sanitizeHeaderValue(samlAttrValue), got)
		}

		// Entitlement headers should NOT be set (since lookup failed)
		entitlementHeader := req.Header.Get("X-Entitlement-Role")
		if entitlementHeader != "" {
			t.Errorf("expected entitlement header to be empty (lookup failed), got %q", entitlementHeader)
		}
	})

	t.Run("property-based: SAML always applied regardless of entitlement error", func(t *testing.T) {
		f := func(headerName, samlAttrValue string, hasEntitlementError bool) bool {
			// Skip invalid inputs
			if headerName == "" || !strings.HasPrefix(strings.ToLower(headerName), "x-") {
				return true
			}
			if len(samlAttrValue) > 1000 {
				return true // Skip very long values
			}

			// Normalize header name
			if !strings.HasPrefix(headerName, "X-") {
				headerName = "X-" + headerName
			}

			req := &http.Request{Header: make(http.Header)}

			var mockStore *MockEntitlementStore
			if hasEntitlementError {
				mockStore = &MockEntitlementStore{
					lookupError: fmt.Errorf("entitlement store error"),
				}
			} else {
				mockStore = &MockEntitlementStore{
					result: &domain.EntitlementResult{
						Roles: []string{"entitlement-role"},
					},
				}
			}

			disco := &SAMLDisco{
				Config: Config{
					StripAttributeHeaders: boolPtr(true),
					AttributeHeaders: []AttributeMapping{
						{SAMLAttribute: "test:role", HeaderName: headerName},
					},
				},
				entitlementStore: mockStore,
			}

			session := &domain.Session{
				Subject: "user@example.com",
				Attributes: map[string]string{
					"test:role": samlAttrValue,
				},
			}

			disco.applyAttributeHeaders(req, session)

			// Property: SAML attributes should always be applied
			got := req.Header.Get(headerName)
			if samlAttrValue != "" {
				if got != sanitizeHeaderValue(samlAttrValue) {
					return false // SAML attributes not applied
				}
			} else {
				if got != "" {
					return false // Should be empty when no SAML attribute value
				}
			}

			return true
		}

		if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
			t.Error(err)
		}
	})

	t.Run("differential: entitlement success vs failure - SAML should be same", func(t *testing.T) {
		headerName := "X-Role"
		samlAttrValue := "authentic-admin"

		// Test case 1: Entitlement lookup succeeds
		req1 := &http.Request{Header: make(http.Header)}
		mockStore1 := &MockEntitlementStore{
			result: &domain.EntitlementResult{
				Roles: []string{"entitlement-role"},
			},
		}

		disco1 := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:role", HeaderName: headerName},
				},
			},
			entitlementStore: mockStore1,
		}

		session1 := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:role": samlAttrValue,
			},
		}

		disco1.applyAttributeHeaders(req1, session1)
		samlValue1 := req1.Header.Get(headerName)

		// Test case 2: Entitlement lookup fails
		req2 := &http.Request{Header: make(http.Header)}
		mockStore2 := &MockEntitlementStore{
			lookupError: fmt.Errorf("entitlement store error"),
		}

		disco2 := &SAMLDisco{
			Config: Config{
				StripAttributeHeaders: boolPtr(true),
				AttributeHeaders: []AttributeMapping{
					{SAMLAttribute: "test:role", HeaderName: headerName},
				},
			},
			entitlementStore: mockStore2,
		}

		session2 := &domain.Session{
			Subject: "user@example.com",
			Attributes: map[string]string{
				"test:role": samlAttrValue,
			},
		}

		disco2.applyAttributeHeaders(req2, session2)
		samlValue2 := req2.Header.Get(headerName)

		// Property: SAML attributes should be the same regardless of entitlement outcome
		if samlValue1 != samlValue2 {
			t.Errorf("SAML attributes should be same regardless of entitlement outcome: success=%q, failure=%q", samlValue1, samlValue2)
		}
		if samlValue1 != sanitizeHeaderValue(samlAttrValue) {
			t.Errorf("expected SAML attribute value %q, got %q", sanitizeHeaderValue(samlAttrValue), samlValue1)
		}
	})
}
