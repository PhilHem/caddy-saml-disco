//go:build unit

package domain

import (
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// Cycle 3: Property-Based Test - No SAML Data Loss
// Property: Every SAML attribute in input exists in output with identical values
func TestCombineAttributes_Property_NoSAMLDataLoss(t *testing.T) {
	f := func(attrName string, attrValues []string, roles []string) bool {
		if attrName == "" || len(attrValues) == 0 {
			return true // skip empty
		}
		saml := map[string][]string{attrName: attrValues}
		local := &EntitlementResult{Roles: roles}

		combined := CombineAttributes(saml, local)

		// Property: Every SAML attribute in input exists in output
		got, exists := combined.SAMLAttributes[attrName]
		if !exists {
			return false
		}
		return reflect.DeepEqual(got, attrValues)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 4: Property-Based Test - No Role Loss
// Property: All roles from local entitlements are preserved
func TestCombineAttributes_Property_NoRoleLoss(t *testing.T) {
	f := func(roles []string) bool {
		local := &EntitlementResult{Roles: roles}
		combined := CombineAttributes(nil, local)

		// Property: All roles preserved
		return reflect.DeepEqual(combined.Roles, roles)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 5: Property-Based Test - Nil Safety
// Property: Function never panics with nil inputs
func TestCombineAttributes_Property_NilSafe(t *testing.T) {
	f := func(hasLocal bool) bool {
		var local *EntitlementResult
		if hasLocal {
			local = &EntitlementResult{Roles: []string{"test"}}
		}
		// Must never panic with nil inputs
		combined := CombineAttributes(nil, local)
		// Struct is always non-nil, just verify it was created
		return combined.SAMLAttributes != nil && combined.Metadata != nil
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Additional property test: No metadata loss
func TestCombineAttributes_Property_NoMetadataLoss(t *testing.T) {
	f := func(metaKey, metaValue string) bool {
		if metaKey == "" {
			return true // skip empty key
		}
		local := &EntitlementResult{
			Metadata: map[string]string{metaKey: metaValue},
		}
		combined := CombineAttributes(nil, local)

		// Property: All metadata preserved
		got, exists := combined.Metadata[metaKey]
		if !exists {
			return false
		}
		return got == metaValue
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 6: Property-Based Test - Idempotence
// Property: Combining twice produces same result
func TestCombineAttributes_Property_Idempotent(t *testing.T) {
	f := func(attrName string, attrValue string, role string) bool {
		if attrName == "" {
			return true
		}
		saml := map[string][]string{attrName: {attrValue}}
		local := &EntitlementResult{Roles: []string{role}}

		first := CombineAttributes(saml, local)
		second := CombineAttributes(first.SAMLAttributes, &EntitlementResult{Roles: first.Roles})

		// Property: Combining twice produces same result
		if !reflect.DeepEqual(first.Roles, second.Roles) {
			return false
		}
		if !reflect.DeepEqual(first.SAMLAttributes, second.SAMLAttributes) {
			return false
		}
		return reflect.DeepEqual(first.Metadata, second.Metadata)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 8: Property-Based Test - Header Injection Prevention
// Property: No CR/LF in any value that could become a header
func TestCombineAttributes_Property_NoHeaderInjection(t *testing.T) {
	f := func(role string, metaKey, metaValue string) bool {
		local := &EntitlementResult{
			Roles:    []string{role},
			Metadata: map[string]string{metaKey: metaValue},
		}
		combined := CombineAttributes(nil, local)

		// Property: No CR/LF in any value that could become a header
		for _, r := range combined.Roles {
			if strings.ContainsAny(r, "\r\n") {
				return false
			}
		}
		for _, v := range combined.Metadata {
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



