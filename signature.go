package caddysamldisco

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"go.uber.org/zap"
)

// VerificationDetails contains metadata about a successful signature verification.
type VerificationDetails struct {
	Algorithm   string    // Signature algorithm (e.g., "RSA-SHA256")
	CertSubject string    // Certificate subject (e.g., "CN=Federation Signer")
	CertExpiry  time.Time // Certificate expiry time
}

// algorithmURIToName maps XML DSig algorithm URIs to human-readable names.
var algorithmURIToName = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          "RSA-SHA1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   "RSA-SHA256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   "RSA-SHA384",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   "RSA-SHA512",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ECDSA-SHA256",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ECDSA-SHA384",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ECDSA-SHA512",
}

// algorithmName converts an XML DSig algorithm URI to a human-readable name.
// Returns the URI unchanged if not recognized.
func algorithmName(uri string) string {
	if name, ok := algorithmURIToName[uri]; ok {
		return name
	}
	return uri
}

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
	certs     []*x509.Certificate // kept for logging cert details on success
	logger    *zap.Logger
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
		certs: certs,
	}
}

// NewXMLDsigVerifierWithLogger creates a verifier with a logger for verification events.
// On successful verification, logs algorithm, cert subject, and cert expiry.
func NewXMLDsigVerifierWithLogger(cert *x509.Certificate, logger *zap.Logger) *XMLDsigVerifier {
	return NewXMLDsigVerifierWithCertsAndLogger([]*x509.Certificate{cert}, logger)
}

// NewXMLDsigVerifierWithCertsAndLogger creates a verifier with multiple certs and a logger.
func NewXMLDsigVerifierWithCertsAndLogger(certs []*x509.Certificate, logger *zap.Logger) *XMLDsigVerifier {
	return &XMLDsigVerifier{
		certStore: &dsig.MemoryX509CertificateStore{
			Roots: certs,
		},
		certs:  certs,
		logger: logger,
	}
}

// Verify validates the XML signature on metadata and returns the validated XML bytes.
// Returns error if signature is invalid, missing, or cannot be verified.
// On success, logs verification details if a logger was configured.
func (v *XMLDsigVerifier) Verify(data []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, &AppError{
			Code:    ErrCodeSignatureInvalid,
			Message: "Failed to parse metadata XML",
			Cause:   err,
		}
	}

	// Extract algorithm before validation for logging
	algorithm := v.extractSignatureAlgorithm(doc.Root())

	ctx := dsig.NewDefaultValidationContext(v.certStore)

	validated, err := ctx.Validate(doc.Root())
	if err != nil {
		return nil, &AppError{
			Code:    ErrCodeSignatureInvalid,
			Message: "Metadata signature verification failed",
			Cause:   err,
		}
	}

	// Log success with verification details
	if v.logger != nil && len(v.certs) > 0 {
		cert := v.certs[0] // Log first cert (typically the one used)
		v.logger.Info("metadata signature verified",
			zap.String("algorithm", algorithmName(algorithm)),
			zap.String("cert_subject", cert.Subject.String()),
			zap.Time("cert_expiry", cert.NotAfter),
		)
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

// extractSignatureAlgorithm extracts the SignatureMethod Algorithm from an XML element.
// Returns empty string if not found.
func (v *XMLDsigVerifier) extractSignatureAlgorithm(root *etree.Element) string {
	// Look for ds:Signature/ds:SignedInfo/ds:SignatureMethod[@Algorithm]
	sig := root.FindElement("./Signature")
	if sig == nil {
		// Try with namespace prefix
		sig = root.FindElement(".//[local-name()='Signature']")
	}
	if sig == nil {
		return ""
	}

	signedInfo := sig.FindElement("./SignedInfo")
	if signedInfo == nil {
		signedInfo = sig.FindElement(".//[local-name()='SignedInfo']")
	}
	if signedInfo == nil {
		return ""
	}

	sigMethod := signedInfo.FindElement("./SignatureMethod")
	if sigMethod == nil {
		sigMethod = signedInfo.FindElement(".//[local-name()='SignatureMethod']")
	}
	if sigMethod == nil {
		return ""
	}

	return sigMethod.SelectAttrValue("Algorithm", "")
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
