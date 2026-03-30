package ports

import "time"

// RequestStore tracks SAML AuthnRequest IDs to prevent replay attacks.
// Implementations must be safe for concurrent use.
type RequestStore interface {
	// Store saves a request ID with its expiry time.
	Store(requestID string, expiry time.Time) error

	// Valid checks if a request ID exists and is not expired.
	// Returns true only once per ID (single-use).
	Valid(requestID string) bool

	// GetAll returns all non-expired request IDs.
	// Used by crewjam/saml for InResponseTo validation.
	GetAll() []string
}
