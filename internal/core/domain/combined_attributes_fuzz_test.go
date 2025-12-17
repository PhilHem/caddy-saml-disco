//go:build unit

package domain

import (
	"testing"
)

// Cycle 9: Fuzz Test - Malformed Inputs
// Property: Function never panics with arbitrary input
func FuzzCombineAttributes(f *testing.F) {
	seeds := []struct {
		attrName, attrVal, role, metaKey, metaVal string
	}{
		{"mail", "user@test.edu", "admin", "dept", "IT"},
		{"", "", "", "", ""},
		{"eduPersonPrincipalName", "user@example.edu", "staff", "department", "Engineering"},
	}

	for _, s := range seeds {
		f.Add(s.attrName, s.attrVal, s.role, s.metaKey, s.metaVal)
	}

	f.Fuzz(func(t *testing.T, attrName, attrVal, role, metaKey, metaVal string) {
		saml := map[string][]string{}
		if attrName != "" {
			saml[attrName] = []string{attrVal}
		}

		local := &EntitlementResult{
			Roles:    []string{role},
			Metadata: map[string]string{metaKey: metaVal},
		}

		// Must never panic
		_ = CombineAttributes(saml, local)
	})
}



