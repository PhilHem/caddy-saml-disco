//go:build unit

package caddysamldisco

import (
	"encoding/json"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// =============================================================================
// ARCH-012: Type Alias Behavioral Differences Property Test
// =============================================================================

// TestTypeAlias_Property_BehavioralEquivalence verifies that root package type aliases
// behave identically to their original types. This property test ensures that:
// 1. Type aliases can be assigned to/from originals
// 2. They have identical field access
// 3. They can be used in the same contexts
// 4. JSON marshaling/unmarshaling produces identical results
func TestTypeAlias_Property_BehavioralEquivalence(t *testing.T) {
	t.Run("Session", func(t *testing.T) {
		f := func(subject string, idpEntityID string, nameIDFormat string, sessionIndex string) bool {
			// Create original domain.Session
			original := domain.Session{
				Subject:      subject,
				Attributes:   map[string]string{"email": "test@example.com"},
				IdPEntityID:  idpEntityID,
				NameIDFormat: nameIDFormat,
				SessionIndex: sessionIndex,
				IssuedAt:     time.Now(),
				ExpiresAt:    time.Now().Add(time.Hour),
			}

			// Assign to root package alias
			var alias Session = original

			// Property: Aliases should have identical field values
			if alias.Subject != original.Subject {
				return false
			}
			if alias.IdPEntityID != original.IdPEntityID {
				return false
			}
			if !reflect.DeepEqual(alias.Attributes, original.Attributes) {
				return false
			}

			// Property: Assigning back should work
			var backToOriginal domain.Session = alias
			if !reflect.DeepEqual(backToOriginal, original) {
				return false
			}

			// Property: JSON marshaling should produce identical results
			originalJSON, err1 := json.Marshal(original)
			aliasJSON, err2 := json.Marshal(alias)
			if err1 != nil || err2 != nil {
				return false
			}
			if string(originalJSON) != string(aliasJSON) {
				return false
			}

			return true
		}

		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("IdPInfo", func(t *testing.T) {
		f := func(entityID string, displayName string, ssoURL string) bool {
			// Create original domain.IdPInfo
			original := domain.IdPInfo{
				EntityID:    entityID,
				DisplayName: displayName,
				SSOURL:      ssoURL,
				SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			}

			// Assign to root package alias
			var alias IdPInfo = original

			// Property: Aliases should have identical field values
			if alias.EntityID != original.EntityID {
				return false
			}
			if alias.DisplayName != original.DisplayName {
				return false
			}
			if alias.SSOURL != original.SSOURL {
				return false
			}

			// Property: Assigning back should work
			var backToOriginal domain.IdPInfo = alias
			if !reflect.DeepEqual(backToOriginal, original) {
				return false
			}

			// Property: JSON marshaling should produce identical results
			originalJSON, err1 := json.Marshal(original)
			aliasJSON, err2 := json.Marshal(alias)
			if err1 != nil || err2 != nil {
				return false
			}
			if string(originalJSON) != string(aliasJSON) {
				return false
			}

			return true
		}

		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("Config", func(t *testing.T) {
		f := func(entityID string, metadataURL string, acsURL string) bool {
			// Create original caddy.Config
			original := caddy.Config{
				EntityID:    entityID,
				MetadataURL: metadataURL,
				AcsURL:      acsURL,
			}

			// Assign to root package alias
			var alias Config = original

			// Property: Aliases should have identical field values
			if alias.EntityID != original.EntityID {
				return false
			}
			if alias.MetadataURL != original.MetadataURL {
				return false
			}
			if alias.AcsURL != original.AcsURL {
				return false
			}

			// Property: Assigning back should work
			var backToOriginal caddy.Config = alias
			if !reflect.DeepEqual(backToOriginal, original) {
				return false
			}

			// Property: JSON marshaling should produce identical results
			originalJSON, err1 := json.Marshal(original)
			aliasJSON, err2 := json.Marshal(alias)
			if err1 != nil || err2 != nil {
				return false
			}
			if string(originalJSON) != string(aliasJSON) {
				return false
			}

			return true
		}

		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("SAMLService_PointerEquivalence", func(t *testing.T) {
		// SAMLService is a struct, but we typically use pointers to it
		// Test that pointer types work correctly with aliases

		// Create original caddy.SAMLService (requires valid parameters)
		// For this test, we'll just verify type compatibility
		var original *caddy.SAMLService
		var alias *SAMLService

		// Property: Pointer types should be assignable
		alias = original
		backToOriginal := (*caddy.SAMLService)(alias)
		if backToOriginal != original {
			t.Error("pointer type alias assignment failed")
		}
	})
}
