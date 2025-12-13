package caddysamldisco

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SignatureVerifier verifies XML signatures on SAML metadata.
// This is a port interface - implementations are adapters.
//
// The interface returns validated bytes (not just error) following goxmldsig
// best practices to prevent signature wrapping attacks. The returned bytes
// should be used for further processing.
type SignatureVerifier interface {
	// Verify validates the XML signature on metadata and returns the
	// validated XML bytes. Returns error if signature is invalid or missing.
	Verify(data []byte) ([]byte, error)
}

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

// XMLDsigVerifier verifies XML signatures using goxmldsig.
// It validates enveloped signatures against trusted certificates.
type XMLDsigVerifier struct {
	certStore dsig.X509CertificateStore
}

// NewXMLDsigVerifier creates a verifier with a single trust anchor certificate.
func NewXMLDsigVerifier(cert *x509.Certificate) *XMLDsigVerifier {
	return NewXMLDsigVerifierWithCerts([]*x509.Certificate{cert})
}

// NewXMLDsigVerifierWithCerts creates a verifier with multiple trust anchor certificates.
// This supports certificate rollover scenarios.
func NewXMLDsigVerifierWithCerts(certs []*x509.Certificate) *XMLDsigVerifier {
	return &XMLDsigVerifier{
		certStore: &dsig.MemoryX509CertificateStore{
			Roots: certs,
		},
	}
}

// Verify validates the XML signature on metadata and returns the validated XML bytes.
// Returns error if signature is invalid, missing, or cannot be verified.
func (v *XMLDsigVerifier) Verify(data []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, &AppError{
			Code:    ErrCodeSignatureInvalid,
			Message: "Failed to parse metadata XML",
			Cause:   err,
		}
	}

	ctx := dsig.NewDefaultValidationContext(v.certStore)

	validated, err := ctx.Validate(doc.Root())
	if err != nil {
		return nil, &AppError{
			Code:    ErrCodeSignatureInvalid,
			Message: "Metadata signature verification failed",
			Cause:   err,
		}
	}

	// Re-serialize the validated element to prevent signature wrapping attacks
	validatedDoc := etree.NewDocument()
	validatedDoc.SetRoot(validated)
	result, err := validatedDoc.WriteToBytes()
	if err != nil {
		return nil, &AppError{
			Code:    ErrCodeServiceError,
			Message: "Failed to serialize validated metadata",
			Cause:   err,
		}
	}
	return result, nil
}

// LoadSigningCertificates loads X.509 certificates from a PEM file.
// Supports multiple certificates in a single file for rotation scenarios.
func LoadSigningCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}

	return certs, nil
}
