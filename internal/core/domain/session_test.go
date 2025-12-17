//go:build unit

package domain

import "testing"

// TestAuthnOptions_HasContextFields verifies AuthnOptions has RequestedAuthnContext and AuthnContextComparison fields.
func TestAuthnOptions_HasContextFields(t *testing.T) {
	opts := AuthnOptions{
		ForceAuthn:             true,
		RequestedAuthnContext:  []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"},
		AuthnContextComparison: "exact",
	}
	if len(opts.RequestedAuthnContext) != 1 {
		t.Error("RequestedAuthnContext should have 1 entry")
	}
	if opts.AuthnContextComparison != "exact" {
		t.Error("AuthnContextComparison should be exact")
	}
}

// TestValidateAuthnContextComparison_ValidValues verifies all valid comparison values are accepted.
func TestValidateAuthnContextComparison_ValidValues(t *testing.T) {
	valid := []string{"exact", "minimum", "maximum", "better", ""}
	for _, v := range valid {
		if err := ValidateAuthnContextComparison(v); err != nil {
			t.Errorf("ValidateAuthnContextComparison(%q) should be valid, got error: %v", v, err)
		}
	}
}

// TestValidateAuthnContextComparison_InvalidValue verifies invalid comparison values are rejected.
func TestValidateAuthnContextComparison_InvalidValue(t *testing.T) {
	if err := ValidateAuthnContextComparison("invalid"); err == nil {
		t.Error("ValidateAuthnContextComparison(invalid) should error")
	}
}



