package signature

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// NoopVerifier is a pass-through verifier for development/testing.
// It returns the input unchanged without verification.
type NoopVerifier struct{}

// NewNoopVerifier creates a new NoopVerifier.
func NewNoopVerifier() *NoopVerifier {
	return &NoopVerifier{}
}

// Verify returns the input unchanged without verification.
func (v *NoopVerifier) Verify(data []byte) ([]byte, error) {
	return data, nil
}

// NoopSigner is a pass-through signer for development/testing.
// It returns the input unchanged without signing.
type NoopSigner struct{}

// NewNoopSigner creates a new NoopSigner.
func NewNoopSigner() *NoopSigner {
	return &NoopSigner{}
}

// Sign returns the input unchanged without signing.
func (s *NoopSigner) Sign(data []byte) ([]byte, error) {
	return data, nil
}

// Ensure implementations satisfy interfaces
var _ ports.SignatureVerifier = (*NoopVerifier)(nil)
var _ ports.MetadataSigner = (*NoopSigner)(nil)



