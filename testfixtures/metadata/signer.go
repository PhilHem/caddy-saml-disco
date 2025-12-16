// Package metadata provides a signed metadata generator for testing.
// It signs SAML metadata XML using the same goxmldsig library used
// by the production XMLDsigVerifier, enabling integration tests
// that verify the full signature verification path.
package metadata

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Signer signs SAML metadata XML for testing.
type Signer struct {
	t           testing.TB
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// New creates a Signer with auto-generated key/certificate.
func New(t testing.TB) *Signer {
	t.Helper()

	key, cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate signing certificate: %v", err)
	}

	return &Signer{
		t:           t,
		privateKey:  key,
		certificate: cert,
	}
}

// Certificate returns the signing certificate for verifier setup.
func (s *Signer) Certificate() *x509.Certificate {
	return s.certificate
}

// Sign signs the given metadata XML and returns signed bytes.
func (s *Signer) Sign(metadata []byte) ([]byte, error) {
	if len(metadata) == 0 {
		return nil, errors.New("empty metadata")
	}

	// Parse the XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(metadata); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty XML document")
	}

	// Create key store from tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{s.certificate.Raw},
		PrivateKey:  s.privateKey,
	}
	keyStore := dsig.TLSCertKeyStore(tlsCert)

	// Create signing context
	signingContext := dsig.NewDefaultSigningContext(keyStore)
	signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	// Sign the root element
	signedRoot, err := signingContext.SignEnveloped(root)
	if err != nil {
		return nil, fmt.Errorf("sign XML: %w", err)
	}

	// Replace root with signed version
	doc.SetRoot(signedRoot)

	// Serialize back to bytes
	signedBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize signed XML: %w", err)
	}

	return signedBytes, nil
}

// SAML metadata namespace constants.
const (
	samlMetadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// GenerateIdPMetadata creates and signs a minimal IdP metadata document.
func (s *Signer) GenerateIdPMetadata(entityID string) ([]byte, error) {
	// Create minimal IdP metadata
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="%s" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, samlMetadataNS, entityID, entityID)

	return s.Sign([]byte(metadata))
}

// GenerateAggregateMetadata creates and signs an EntitiesDescriptor with multiple IdPs.
func (s *Signer) GenerateAggregateMetadata(entityIDs []string) ([]byte, error) {
	// Build entity descriptors
	var entities string
	for _, id := range entityIDs {
		entities += fmt.Sprintf(`
  <EntityDescriptor entityID="%s">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>`, id, id)
	}

	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="%s" Name="Test Federation">%s
</EntitiesDescriptor>`, samlMetadataNS, entities)

	return s.Sign([]byte(metadata))
}

// generateSelfSignedCert creates a self-signed certificate for signing.
func generateSelfSignedCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Metadata Signer",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}

	return key, cert, nil
}
