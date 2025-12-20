//go:build unit

package caddysamldisco

import (
	"reflect"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// =============================================================================
// ARCH-009: Differential Test for Root Package Re-exports vs Direct Internal Imports
// =============================================================================
//
// This test verifies that root package re-exports (type aliases and var re-exports)
// behave identically to direct imports from internal packages. This ensures that
// the architectural violation (root package re-exports) does not introduce
// behavioral differences that could cause bugs.

// TestRootReexport_Differential_TypeAliasEquivalence tests that type aliases in root
// package are equivalent to direct internal types in terms of type identity and reflection.
func TestRootReexport_Differential_TypeAliasEquivalence(t *testing.T) {
	tests := []struct {
		name          string
		rootType      reflect.Type
		internalType  reflect.Type
		rootValue     interface{}
		internalValue interface{}
	}{
		{
			name:          "IdPInfo type alias",
			rootType:      reflect.TypeOf((*IdPInfo)(nil)).Elem(),
			internalType:  reflect.TypeOf((*domain.IdPInfo)(nil)).Elem(),
			rootValue:     IdPInfo{},
			internalValue: domain.IdPInfo{},
		},
		{
			name:          "Session type alias",
			rootType:      reflect.TypeOf((*Session)(nil)).Elem(),
			internalType:  reflect.TypeOf((*domain.Session)(nil)).Elem(),
			rootValue:     Session{},
			internalValue: domain.Session{},
		},
		{
			name:          "ErrorCode type alias",
			rootType:      reflect.TypeOf((*ErrorCode)(nil)).Elem(),
			internalType:  reflect.TypeOf((*domain.ErrorCode)(nil)).Elem(),
			rootValue:     ErrorCode(""),
			internalValue: domain.ErrorCode(""),
		},
		{
			name:          "MetadataStore interface alias",
			rootType:      reflect.TypeOf((*MetadataStore)(nil)).Elem(),
			internalType:  reflect.TypeOf((*ports.MetadataStore)(nil)).Elem(),
			rootValue:     (*MetadataStore)(nil),
			internalValue: (*ports.MetadataStore)(nil),
		},
		{
			name:          "SessionStore interface alias",
			rootType:      reflect.TypeOf((*SessionStore)(nil)).Elem(),
			internalType:  reflect.TypeOf((*ports.SessionStore)(nil)).Elem(),
			rootValue:     (*SessionStore)(nil),
			internalValue: (*ports.SessionStore)(nil),
		},
		{
			name:          "Config type alias",
			rootType:      reflect.TypeOf((*Config)(nil)).Elem(),
			internalType:  reflect.TypeOf((*caddyadapter.Config)(nil)).Elem(),
			rootValue:     Config{},
			internalValue: caddyadapter.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test 1: Type identity via reflect.Type
			if tt.rootType != tt.internalType {
				t.Errorf("Type identity mismatch: root type %v != internal type %v",
					tt.rootType, tt.internalType)
			}

			// Test 2: Type name comparison
			if tt.rootType.Name() != tt.internalType.Name() {
				t.Errorf("Type name mismatch: root %q != internal %q",
					tt.rootType.Name(), tt.internalType.Name())
			}

			// Test 3: Type string representation
			if tt.rootType.String() != tt.internalType.String() {
				t.Errorf("Type string mismatch: root %q != internal %q",
					tt.rootType.String(), tt.internalType.String())
			}

			// Test 4: Value type reflection
			rootValType := reflect.TypeOf(tt.rootValue)
			internalValType := reflect.TypeOf(tt.internalValue)
			if rootValType != internalValType {
				t.Errorf("Value type mismatch: root %v != internal %v",
					rootValType, internalValType)
			}
		})
	}
}

// TestRootReexport_Differential_VarReexportEquivalence tests that var re-exports
// in root package point to the same functions/variables as direct internal imports.
func TestRootReexport_Differential_VarReexportEquivalence(t *testing.T) {
	tests := []struct {
		name        string
		rootVar     interface{}
		internalVar interface{}
		description string
	}{
		{
			name:        "ResolveAttributeName function",
			rootVar:     ResolveAttributeName,
			internalVar: domain.ResolveAttributeName,
			description: "Function pointer equality",
		},
		{
			name:        "IsMetadataExpired function",
			rootVar:     IsMetadataExpired,
			internalVar: domain.IsMetadataExpired,
			description: "Function pointer equality",
		},
		{
			name:        "MatchesEntityIDPattern function",
			rootVar:     MatchesEntityIDPattern,
			internalVar: domain.MatchesEntityIDPattern,
			description: "Function pointer equality",
		},
		{
			name:        "ErrIdPNotFound error",
			rootVar:     ErrIdPNotFound,
			internalVar: domain.ErrIdPNotFound,
			description: "Error variable equality",
		},
		{
			name:        "ErrSessionNotFound error",
			rootVar:     ErrSessionNotFound,
			internalVar: ports.ErrSessionNotFound,
			description: "Error variable equality",
		},
		{
			name:        "MapAttributesToHeaders function",
			rootVar:     MapAttributesToHeaders,
			internalVar: caddyadapter.MapAttributesToHeaders,
			description: "Function pointer equality",
		},
		{
			name:        "ApplyHeaderPrefix function",
			rootVar:     ApplyHeaderPrefix,
			internalVar: caddyadapter.ApplyHeaderPrefix,
			description: "Function pointer equality",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test 1: Pointer equality (should be same function/variable)
			rootPtr := reflect.ValueOf(tt.rootVar).Pointer()
			internalPtr := reflect.ValueOf(tt.internalVar).Pointer()
			if rootPtr != internalPtr {
				t.Errorf("Pointer mismatch: root %p != internal %p (%s)",
					tt.rootVar, tt.internalVar, tt.description)
			}

			// Test 2: Type equality
			rootType := reflect.TypeOf(tt.rootVar)
			internalType := reflect.TypeOf(tt.internalVar)
			if rootType != internalType {
				t.Errorf("Type mismatch: root %v != internal %v",
					rootType, internalType)
			}
		})
	}
}

// TestRootReexport_Differential_FunctionBehaviorEquivalence tests that re-exported
// functions produce identical results when called with the same inputs.
func TestRootReexport_Differential_FunctionBehaviorEquivalence(t *testing.T) {
	// Test ResolveAttributeName
	t.Run("ResolveAttributeName", func(t *testing.T) {
		testCases := []string{
			"urn:oid:0.9.2342.19200300.100.1.3",
			"mail",
			"urn:oid:2.5.4.3",
			"cn",
		}

		for _, attr := range testCases {
			rootOID, rootFriendly := ResolveAttributeName(attr)
			internalOID, internalFriendly := domain.ResolveAttributeName(attr)
			if rootOID != internalOID || rootFriendly != internalFriendly {
				t.Errorf("ResolveAttributeName(%q): root=(%q, %q), internal=(%q, %q)",
					attr, rootOID, rootFriendly, internalOID, internalFriendly)
			}
		}
	})

	// Test IsMetadataExpired
	t.Run("IsMetadataExpired", func(t *testing.T) {
		now := time.Now()
		// Test with zero time (not expired)
		zeroTime := time.Time{}
		rootResult := IsMetadataExpired(zeroTime, now)
		internalResult := domain.IsMetadataExpired(zeroTime, now)
		if rootResult != internalResult {
			t.Errorf("IsMetadataExpired(zero, now): root=%v, internal=%v",
				rootResult, internalResult)
		}

		// Test with past time (expired)
		pastTime, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
		rootResult = IsMetadataExpired(pastTime, now)
		internalResult = domain.IsMetadataExpired(pastTime, now)
		if rootResult != internalResult {
			t.Errorf("IsMetadataExpired(past, now): root=%v, internal=%v",
				rootResult, internalResult)
		}
	})

	// Test MatchesEntityIDPattern
	t.Run("MatchesEntityIDPattern", func(t *testing.T) {
		testCases := []struct {
			pattern  string
			entityID string
		}{
			{"*", "https://idp.example.com"},
			{"https://idp.example.com", "https://idp.example.com"},
			{"https://*.example.com", "https://idp.example.com"},
			{"https://other.example.com", "https://idp.example.com"},
		}

		for _, tc := range testCases {
			rootResult := MatchesEntityIDPattern(tc.pattern, tc.entityID)
			internalResult := domain.MatchesEntityIDPattern(tc.pattern, tc.entityID)
			if rootResult != internalResult {
				t.Errorf("MatchesEntityIDPattern(%q, %q): root=%v, internal=%v",
					tc.pattern, tc.entityID, rootResult, internalResult)
			}
		}
	})

	// Test MapAttributesToHeaders
	t.Run("MapAttributesToHeaders", func(t *testing.T) {
		attrs := map[string][]string{
			"urn:oid:0.9.2342.19200300.100.1.3": {"user@example.com"},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "urn:oid:0.9.2342.19200300.100.1.3", HeaderName: "X-Mail"},
		}

		rootResult, rootErr := MapAttributesToHeaders(attrs, mappings)
		internalMappings := []caddyadapter.AttributeMapping{
			{SAMLAttribute: "urn:oid:0.9.2342.19200300.100.1.3", HeaderName: "X-Mail"},
		}
		internalResult, internalErr := caddyadapter.MapAttributesToHeaders(attrs, internalMappings)

		if (rootErr != nil) != (internalErr != nil) {
			t.Errorf("Error mismatch: root=%v, internal=%v", rootErr, internalErr)
		}
		if rootErr == nil && internalErr == nil {
			if len(rootResult) != len(internalResult) {
				t.Errorf("Result length mismatch: root=%d, internal=%d",
					len(rootResult), len(internalResult))
			}
			for k, v := range rootResult {
				if internalResult[k] != v {
					t.Errorf("Result[%q] mismatch: root=%q, internal=%q",
						k, v, internalResult[k])
				}
			}
		}
	})
}

// TestRootReexport_Differential_InterfaceSatisfaction tests that type aliases
// satisfy the same interfaces as their internal counterparts.
func TestRootReexport_Differential_InterfaceSatisfaction(t *testing.T) {
	// Test MetadataStore interface
	t.Run("MetadataStore interface", func(t *testing.T) {
		// Create an implementation using internal type
		store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
			{EntityID: "https://idp.example.com"},
		})

		// Both root and internal interfaces should accept the same implementation
		var rootStore MetadataStore = store
		var internalStore ports.MetadataStore = store

		if rootStore == nil || internalStore == nil {
			t.Error("Interface assignment failed")
		}

		// Verify both can call the same methods
		rootIdPs, rootErr := rootStore.ListIdPs("")
		internalIdPs, internalErr := internalStore.ListIdPs("")

		if (rootErr != nil) != (internalErr != nil) {
			t.Errorf("Error mismatch: root=%v, internal=%v", rootErr, internalErr)
		}
		if len(rootIdPs) != len(internalIdPs) {
			t.Errorf("Result length mismatch: root=%d, internal=%d",
				len(rootIdPs), len(internalIdPs))
		}
	})

	// Test SessionStore interface
	t.Run("SessionStore interface", func(t *testing.T) {
		// Create an implementation using internal type
		// Use a test key - for this test we just need to verify interface assignment works
		key, err := LoadPrivateKey("testdata/sp-key.pem")
		if err != nil {
			t.Fatalf("failed to load test key: %v", err)
		}
		store := NewCookieSessionStore(key, 8*time.Hour)

		// Both root and internal interfaces should accept the same implementation
		var rootStore SessionStore = store
		var internalStore ports.SessionStore = store

		if rootStore == nil || internalStore == nil {
			t.Error("Interface assignment failed")
		}
	})

	// Test LogoStore interface
	t.Run("LogoStore interface", func(t *testing.T) {
		store := logo.NewInMemoryLogoStore()

		var rootStore LogoStore = store
		var internalStore ports.LogoStore = store

		if rootStore == nil || internalStore == nil {
			t.Error("Interface assignment failed")
		}
	})

	// Test MetricsRecorder interface
	t.Run("MetricsRecorder interface", func(t *testing.T) {
		store := metrics.NewNoopMetricsRecorder()

		var rootStore MetricsRecorder = store
		var internalStore ports.MetricsRecorder = store

		if rootStore == nil || internalStore == nil {
			t.Error("Interface assignment failed")
		}
	})

	// Test RequestStore interface
	t.Run("RequestStore interface", func(t *testing.T) {
		store := request.NewInMemoryRequestStore()

		var rootStore RequestStore = store
		var internalStore ports.RequestStore = store

		if rootStore == nil || internalStore == nil {
			t.Error("Interface assignment failed")
		}
	})

	// Test SignatureVerifier interface
	t.Run("SignatureVerifier interface", func(t *testing.T) {
		verifier := signature.NewNoopVerifier()

		var rootVerifier SignatureVerifier = verifier
		var internalVerifier ports.SignatureVerifier = verifier

		if rootVerifier == nil || internalVerifier == nil {
			t.Error("Interface assignment failed")
		}
	})
}

// TestRootReexport_Differential_StructTypeAliases tests that struct type aliases
// have identical field access and method sets.
func TestRootReexport_Differential_StructTypeAliases(t *testing.T) {
	// Test IdPInfo struct
	t.Run("IdPInfo struct", func(t *testing.T) {
		rootIdP := IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
		}
		internalIdP := domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
		}

		// Test field access
		if rootIdP.EntityID != internalIdP.EntityID {
			t.Errorf("EntityID mismatch: root=%q, internal=%q",
				rootIdP.EntityID, internalIdP.EntityID)
		}
		if rootIdP.DisplayName != internalIdP.DisplayName {
			t.Errorf("DisplayName mismatch: root=%q, internal=%q",
				rootIdP.DisplayName, internalIdP.DisplayName)
		}

		// Test type conversion (should be no-op for type aliases)
		converted := IdPInfo(internalIdP)
		if converted.EntityID != rootIdP.EntityID {
			t.Errorf("Type conversion failed: converted=%q, expected=%q",
				converted.EntityID, rootIdP.EntityID)
		}
	})

	// Test Session struct
	t.Run("Session struct", func(t *testing.T) {
		rootSession := Session{
			Subject: "user@example.com",
		}
		internalSession := domain.Session{
			Subject: "user@example.com",
		}

		if rootSession.Subject != internalSession.Subject {
			t.Errorf("Subject mismatch: root=%q, internal=%q",
				rootSession.Subject, internalSession.Subject)
		}

		// Test type conversion
		converted := Session(internalSession)
		if converted.Subject != rootSession.Subject {
			t.Errorf("Type conversion failed: converted=%q, expected=%q",
				converted.Subject, rootSession.Subject)
		}
	})

	// Test Config struct
	t.Run("Config struct", func(t *testing.T) {
		rootConfig := Config{}
		internalConfig := caddyadapter.Config{}

		// Both should have same zero values
		rootType := reflect.TypeOf(rootConfig)
		internalType := reflect.TypeOf(internalConfig)
		if rootType != internalType {
			t.Errorf("Config type mismatch: root=%v, internal=%v",
				rootType, internalType)
		}
	})
}

// =============================================================================
// ARCH-035: Port Contract Verification Tests for Root Package Re-exports
// =============================================================================
//
// These tests verify that port interface contracts (error handling, behavioral
// guarantees, type conversions) are maintained when accessing through root
// package re-exports vs direct internal imports.

// TestRootReexport_PortContract_ErrorHandling (ARCH-035) verifies that error
// handling through root package re-exports matches direct internal imports.
func TestRootReexport_PortContract_ErrorHandling(t *testing.T) {
	// Test invalid header names produce same errors through root package vs direct imports
	testCases := []struct {
		name        string
		headerName  string
		expectError bool
	}{
		{"no X- prefix", "Invalid-Header", true},
		{"invalid characters", "X-Header@Name", true},
		{"too short", "X-", true},
		{"valid header", "X-Valid-Header", false},
		{"lowercase x prefix", "x-valid-header", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string][]string{
				"mail": {"user@example.com"},
			}

			// Test through root package re-exports
			rootMappings := []AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: tc.headerName},
			}
			rootResult, rootErr := MapAttributesToHeaders(attrs, rootMappings)

			// Test through direct internal imports
			internalMappings := []caddyadapter.AttributeMapping{
				{SAMLAttribute: "mail", HeaderName: tc.headerName},
			}
			internalResult, internalErr := caddyadapter.MapAttributesToHeaders(attrs, internalMappings)

			// Verify error presence matches
			if (rootErr != nil) != (internalErr != nil) {
				t.Errorf("Error presence mismatch: root=%v, internal=%v", rootErr != nil, internalErr != nil)
				return
			}

			// If errors expected, verify error messages are identical
			if tc.expectError {
				if rootErr == nil || internalErr == nil {
					t.Errorf("Expected error but got: root=%v, internal=%v", rootErr, internalErr)
					return
				}
				if rootErr.Error() != internalErr.Error() {
					t.Errorf("Error message mismatch:\nroot:     %q\ninternal: %q", rootErr.Error(), internalErr.Error())
				}
			} else {
				// If no error expected, verify results match
				if rootErr != nil || internalErr != nil {
					t.Errorf("Unexpected error: root=%v, internal=%v", rootErr, internalErr)
					return
				}
				if len(rootResult) != len(internalResult) {
					t.Errorf("Result length mismatch: root=%d, internal=%d", len(rootResult), len(internalResult))
					return
				}
				for k, v := range rootResult {
					if internalResult[k] != v {
						t.Errorf("Result[%q] mismatch: root=%q, internal=%q", k, v, internalResult[k])
					}
				}
			}
		})
	}
}

// TestRootReexport_PortContract_BehavioralGuarantees (ARCH-035) verifies that
// behavioral guarantees (security guarantees, validation rules) are maintained
// through root package re-exports.
func TestRootReexport_PortContract_BehavioralGuarantees(t *testing.T) {
	// Test 1: Header name validation (must start with "X-") works identically
	t.Run("Header name validation", func(t *testing.T) {
		invalidHeaders := []string{
			"Invalid-Header", // No X- prefix
			"X-Header@Name",  // Invalid character
			"X-",             // Too short
		}

		for _, headerName := range invalidHeaders {
			// Test through root package
			rootValid := IsValidHeaderName(headerName)

			// Test through direct internal import
			internalValid := domain.IsValidHeaderName(headerName)

			if rootValid != internalValid {
				t.Errorf("IsValidHeaderName(%q) mismatch: root=%v, internal=%v", headerName, rootValid, internalValid)
			}
		}

		// Test valid headers
		validHeaders := []string{
			"X-Valid-Header",
			"x-lowercase-prefix",
			"X-123-Numbers",
		}

		for _, headerName := range validHeaders {
			rootValid := IsValidHeaderName(headerName)
			internalValid := domain.IsValidHeaderName(headerName)

			if rootValid != internalValid {
				t.Errorf("IsValidHeaderName(%q) mismatch: root=%v, internal=%v", headerName, rootValid, internalValid)
			}
			if !rootValid {
				t.Errorf("IsValidHeaderName(%q) should return true but got false", headerName)
			}
		}
	})

	// Test 2: Missing attributes produce no header (not empty string) - same behavior
	t.Run("Missing attributes produce no header", func(t *testing.T) {
		attrs := map[string][]string{
			"other-attr": {"value"},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "nonexistent-attr", HeaderName: "X-Missing"},
		}

		// Test through root package
		rootResult, rootErr := MapAttributesToHeaders(attrs, mappings)

		// Test through direct internal import
		internalMappings := []caddyadapter.AttributeMapping{
			{SAMLAttribute: "nonexistent-attr", HeaderName: "X-Missing"},
		}
		internalResult, internalErr := caddyadapter.MapAttributesToHeaders(attrs, internalMappings)

		// Verify no errors
		if rootErr != nil || internalErr != nil {
			t.Errorf("Unexpected errors: root=%v, internal=%v", rootErr, internalErr)
			return
		}

		// Verify missing attribute produces no header (not empty string)
		if len(rootResult) != 0 {
			t.Errorf("Expected no headers for missing attribute, got: %v", rootResult)
		}
		if len(internalResult) != 0 {
			t.Errorf("Expected no headers for missing attribute (internal), got: %v", internalResult)
		}

		// Verify results match
		if len(rootResult) != len(internalResult) {
			t.Errorf("Result length mismatch: root=%d, internal=%d", len(rootResult), len(internalResult))
		}
	})

	// Test 3: Header value sanitization produces identical results
	t.Run("Header value sanitization", func(t *testing.T) {
		attrs := map[string][]string{
			"mail": {"user@example.com", "admin@example.com"},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail", Separator: ";"},
		}

		// Test through root package
		rootResult, rootErr := MapAttributesToHeaders(attrs, mappings)

		// Test through direct internal import
		internalMappings := []caddyadapter.AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail", Separator: ";"},
		}
		internalResult, internalErr := caddyadapter.MapAttributesToHeaders(attrs, internalMappings)

		// Verify no errors
		if rootErr != nil || internalErr != nil {
			t.Errorf("Unexpected errors: root=%v, internal=%v", rootErr, internalErr)
			return
		}

		// Verify results are identical
		if len(rootResult) != len(internalResult) {
			t.Errorf("Result length mismatch: root=%d, internal=%d", len(rootResult), len(internalResult))
			return
		}
		for k, v := range rootResult {
			if internalResult[k] != v {
				t.Errorf("Result[%q] mismatch: root=%q, internal=%q", k, v, internalResult[k])
			}
		}
	})
}

// TestRootReexport_PortContract_TypeConversions (ARCH-035) verifies that type
// conversions between root package types and port types work correctly.
func TestRootReexport_PortContract_TypeConversions(t *testing.T) {
	// Test 1: AttributeMapping (root) → PortAttributeMapping conversion preserves all fields
	t.Run("AttributeMapping to PortAttributeMapping conversion", func(t *testing.T) {
		rootMapping := AttributeMapping{
			SAMLAttribute: "urn:oid:0.9.2342.19200300.100.1.3",
			HeaderName:    "X-Mail",
			Separator:     ";",
		}

		// Convert to PortAttributeMapping (type alias, should be no-op)
		portMapping := PortAttributeMapping(rootMapping)

		// Verify all fields preserved
		if portMapping.SAMLAttribute != rootMapping.SAMLAttribute {
			t.Errorf("SAMLAttribute mismatch: port=%q, root=%q", portMapping.SAMLAttribute, rootMapping.SAMLAttribute)
		}
		if portMapping.HeaderName != rootMapping.HeaderName {
			t.Errorf("HeaderName mismatch: port=%q, root=%q", portMapping.HeaderName, rootMapping.HeaderName)
		}
		if portMapping.Separator != rootMapping.Separator {
			t.Errorf("Separator mismatch: port=%q, root=%q", portMapping.Separator, rootMapping.Separator)
		}
	})

	// Test 2: Roundtrip conversion works correctly
	t.Run("Roundtrip conversion", func(t *testing.T) {
		original := AttributeMapping{
			SAMLAttribute: "mail",
			HeaderName:    "X-Email",
			Separator:     ",",
		}

		// Convert to PortAttributeMapping and back
		portMapping := PortAttributeMapping(original)
		backToRoot := AttributeMapping(portMapping)

		// Verify roundtrip preserves all fields
		if backToRoot.SAMLAttribute != original.SAMLAttribute {
			t.Errorf("SAMLAttribute mismatch after roundtrip: original=%q, result=%q", original.SAMLAttribute, backToRoot.SAMLAttribute)
		}
		if backToRoot.HeaderName != original.HeaderName {
			t.Errorf("HeaderName mismatch after roundtrip: original=%q, result=%q", original.HeaderName, backToRoot.HeaderName)
		}
		if backToRoot.Separator != original.Separator {
			t.Errorf("Separator mismatch after roundtrip: original=%q, result=%q", original.Separator, backToRoot.Separator)
		}
	})

	// Test 3: Type assertions work (AttributeMapper interface through root package)
	t.Run("AttributeMapper interface type assertion", func(t *testing.T) {
		// Create mapper via root package
		mapper := NewCaddyAttributeMapper()

		// Verify it satisfies AttributeMapper interface (root package type alias)
		var rootMapper AttributeMapper = mapper
		if rootMapper == nil {
			t.Error("AttributeMapper (root package) type assertion failed")
		}

		// Verify it also satisfies ports.AttributeMapper interface (direct internal import)
		var internalMapper ports.AttributeMapper = mapper
		if internalMapper == nil {
			t.Error("ports.AttributeMapper (internal) type assertion failed")
		}

		// Test that both interfaces work identically
		attrs := map[string][]string{
			"mail": {"user@example.com"},
		}
		rootMappings := []PortAttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail"},
		}
		internalMappings := []ports.AttributeMapping{
			{SAMLAttribute: "mail", HeaderName: "X-Mail"},
		}

		rootResult, rootErr := rootMapper.MapAttributesToHeaders(attrs, rootMappings)
		internalResult, internalErr := internalMapper.MapAttributesToHeaders(attrs, internalMappings)

		// Verify both produce identical results
		if (rootErr != nil) != (internalErr != nil) {
			t.Errorf("Error presence mismatch: root=%v, internal=%v", rootErr != nil, internalErr != nil)
			return
		}
		if rootErr == nil && internalErr == nil {
			if len(rootResult) != len(internalResult) {
				t.Errorf("Result length mismatch: root=%d, internal=%d", len(rootResult), len(internalResult))
				return
			}
			for k, v := range rootResult {
				if internalResult[k] != v {
					t.Errorf("Result[%q] mismatch: root=%q, internal=%q", k, v, internalResult[k])
				}
			}
		}
	})
}


