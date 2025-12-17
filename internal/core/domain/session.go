package domain

import (
	"fmt"
	"time"
)

// Session holds authenticated user information.
// This is the core domain model - it has no external dependencies.
type Session struct {
	// Subject is the SAML NameID (user identifier).
	Subject string

	// Attributes contains SAML attributes from the assertion.
	Attributes map[string]string

	// IdPEntityID identifies which IdP authenticated the user.
	IdPEntityID string

	// NameIDFormat is the format of the NameID (needed for LogoutRequest).
	NameIDFormat string

	// SessionIndex is the IdP session index (needed for LogoutRequest).
	SessionIndex string

	// IssuedAt is when the session was created.
	IssuedAt time.Time

	// ExpiresAt is when the session expires.
	ExpiresAt time.Time
}

// AuthnOptions controls SAML authentication request parameters.
type AuthnOptions struct {
	// ForceAuthn requests fresh authentication from the IdP.
	// When true, the IdP must re-authenticate the user even if they have a valid session.
	ForceAuthn bool

	// RequestedAuthnContext is a list of authentication context class URIs to request from the IdP.
	// Examples:
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	//   - "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
	// If empty, no RequestedAuthnContext element is included in the AuthnRequest.
	RequestedAuthnContext []string

	// AuthnContextComparison specifies how the IdP should match the requested context.
	// Valid values: "exact", "minimum", "maximum", "better", or "" (defaults to "exact").
	// See SAML 2.0 Core specification section 3.3.2.2.1 for details.
	AuthnContextComparison string
}

var validComparisons = map[string]bool{
	"":        true, // default to "exact" per SAML spec
	"exact":   true,
	"minimum": true,
	"maximum": true,
	"better":  true,
}

// ValidateAuthnContextComparison validates that the comparison value is valid per SAML 2.0 spec.
// Returns an error if the value is invalid, nil otherwise.
func ValidateAuthnContextComparison(c string) error {
	if !validComparisons[c] {
		return fmt.Errorf("invalid AuthnContextComparison: %q (must be one of: exact, minimum, maximum, better, or empty)", c)
	}
	return nil
}



