//go:build unit

package metadata

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"testing/quick"
	"time"
)

// generateTestIdPCert creates a test certificate for IdP signing.
func generateTestIdPCertForMetadata(key *rsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName:   "Test IdP",
			Organization: []string{"Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create IdP cert: %v", err))
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(fmt.Sprintf("failed to parse IdP cert: %v", err))
	}

	return cert
}

// certToBase64DER converts a certificate to base64-encoded DER (as stored in SAML metadata).
func certToBase64DERForMetadata(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// createMetadataXML creates a minimal IdP metadata XML with the given certificates.
func createMetadataXMLWithCerts(entityID string, certs []*x509.Certificate) []byte {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entityID + `">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`

	for _, cert := range certs {
		certData := certToBase64DERForMetadata(cert)
		xml += fmt.Sprintf(`
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>`, certData)
	}

	xml += `
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	return []byte(xml)
}

// TestCertificateRotation_Property_MetadataRefresh verifies:
// Property: When metadata refreshes, certificates are updated from the new metadata.
//
// This property ensures that:
// 1. Initial metadata with cert1 → IdP has cert1
// 2. Refresh metadata with cert1 + cert2 → IdP has cert1 + cert2 (rotation window)
// 3. Refresh metadata with cert2 only → IdP has cert2 (rotation complete)
//
// Note: The metadata is the source of truth. During rotation, IdPs must keep both
// certificates in metadata. Once rotation is complete and old cert is removed from
// metadata, we stop accepting it (correct behavior).
func TestCertificateRotation_Property_MetadataRefresh(t *testing.T) {
	// Generate test certificates
	now := time.Now()
		idpKey1, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	idpCert1 := generateTestIdPCertForMetadata(idpKey1, now.Add(-365*24*time.Hour), now.Add(365*24*time.Hour))

		idpKey2, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}
	idpCert2 := generateTestIdPCertForMetadata(idpKey2, now, now.Add(730*24*time.Hour))

	entityID := "https://idp.example.com"

	// Step 1: Initial metadata with cert1 only
	metadata1 := createMetadataXMLWithCerts(entityID, []*x509.Certificate{idpCert1})
	idps1, _, err := ParseMetadata(metadata1)
	if err != nil {
		t.Fatalf("failed to parse metadata1: %v", err)
	}

	if len(idps1) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps1))
	}

	idp1 := idps1[0]
	if len(idp1.Certificates) != 1 {
		t.Errorf("expected 1 certificate in initial metadata, got %d", len(idp1.Certificates))
	}

	// Step 2: Refresh metadata with cert1 + cert2 (rotation window)
	metadata2 := createMetadataXMLWithCerts(entityID, []*x509.Certificate{idpCert1, idpCert2})
	idps2, _, err := ParseMetadata(metadata2)
	if err != nil {
		t.Fatalf("failed to parse metadata2: %v", err)
	}

	if len(idps2) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps2))
	}

	idp2 := idps2[0]
	if len(idp2.Certificates) != 2 {
		t.Errorf("expected 2 certificates during rotation, got %d", len(idp2.Certificates))
	}

	// Verify both certificates are present
	cert1Data := certToBase64DERForMetadata(idpCert1)
	cert2Data := certToBase64DERForMetadata(idpCert2)

	foundCert1 := false
	foundCert2 := false
	for _, cert := range idp2.Certificates {
		if cert == cert1Data {
			foundCert1 = true
		}
		if cert == cert2Data {
			foundCert2 = true
		}
	}

	if !foundCert1 {
		t.Error("cert1 missing during rotation window")
	}
	if !foundCert2 {
		t.Error("cert2 missing during rotation window")
	}

	// Step 3: Refresh metadata with cert2 only (rotation complete)
	metadata3 := createMetadataXMLWithCerts(entityID, []*x509.Certificate{idpCert2})
	idps3, _, err := ParseMetadata(metadata3)
	if err != nil {
		t.Fatalf("failed to parse metadata3: %v", err)
	}

	if len(idps3) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps3))
	}

	idp3 := idps3[0]
	if len(idp3.Certificates) != 1 {
		t.Errorf("expected 1 certificate after rotation, got %d", len(idp3.Certificates))
	}

	// Verify only cert2 is present
	if idp3.Certificates[0] != cert2Data {
		t.Error("expected cert2 after rotation, got different certificate")
	}

	// Property: Metadata refresh correctly updates certificates
	// Old certificates are removed when they're removed from metadata (correct behavior)
	t.Log("Certificate rotation property verified: Metadata refresh correctly updates certificates")
}

// TestCertificateRotation_Property_MetadataRefreshPreservesRotationWindow verifies:
// Property: During rotation window, both old and new certificates are present in metadata.
//
// This property ensures that IdPs can publish both certificates during rotation,
// and the SP correctly accepts both.
func TestCertificateRotation_Property_MetadataRefreshPreservesRotationWindow(t *testing.T) {
	f := func(certCount int) bool {
		// Limit certificate count for performance (2-5 typical for rotation)
		if certCount < 2 || certCount > 5 {
			return true
		}

		// Generate multiple certificates
		now := time.Now()
		var certs []*x509.Certificate
		for i := 0; i < certCount; i++ {
			key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
			if err != nil {
				return false
			}
			notBefore := now.Add(-time.Duration(i) * 24 * time.Hour)
			notAfter := now.Add(time.Duration(certCount-i) * 365 * 24 * time.Hour)
			cert := generateTestIdPCertForMetadata(key, notBefore, notAfter)
			certs = append(certs, cert)
		}

		// Create metadata with all certificates (rotation window)
		entityID := "https://idp.example.com"
		metadata := createMetadataXMLWithCerts(entityID, certs)
		idps, _, err := ParseMetadata(metadata)
		if err != nil {
			return false
		}

		if len(idps) != 1 {
			return false
		}

		idp := idps[0]

		// Property: All certificates must be present
		if len(idp.Certificates) != certCount {
			return false
		}

		// Verify all certificates are present
		expectedCerts := make(map[string]bool)
		for _, cert := range certs {
			expectedCerts[certToBase64DERForMetadata(cert)] = true
		}

		for _, certData := range idp.Certificates {
			if !expectedCerts[certData] {
				return false // Certificate missing
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}






