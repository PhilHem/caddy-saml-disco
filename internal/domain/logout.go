package domain

// RawLogoutResponse represents an unvalidated SAML LogoutResponse from the wire.
type RawLogoutResponse struct {
	Encoded string // base64-encoded SAMLResponse parameter
	Binding string // "redirect" or "POST"
}

// ValidatedLogoutResponse represents a LogoutResponse that has passed validation.
type ValidatedLogoutResponse struct {
	StatusCode   string
	InResponseTo string
	Issuer       string
}
