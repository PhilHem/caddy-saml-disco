//go:build unit

package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// generateTestCert generates a test certificate and private key.
func generateTestCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// TestNoopVerifier_Interface verifies the interface contract.
func TestNoopVerifier_Interface(t *testing.T) {
	var _ ports.SignatureVerifier = (*NoopVerifier)(nil)
}

// TestNoopVerifier_Verify verifies Verify returns input unchanged.
func TestNoopVerifier_Verify(t *testing.T) {
	verifier := NewNoopVerifier()

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("test data")},
		{"xml", []byte(`<?xml version="1.0"?><root><child>value</child></root>`)},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := verifier.Verify(tc.data)
			if err != nil {
				t.Errorf("Verify() returned error: %v", err)
			}
			if string(result) != string(tc.data) {
				t.Errorf("Verify() = %q, want %q", result, tc.data)
			}
		})
	}
}

// TestNoopSigner_Interface verifies the interface contract.
func TestNoopSigner_Interface(t *testing.T) {
	var _ ports.MetadataSigner = (*NoopSigner)(nil)
}

// TestNoopSigner_Sign verifies Sign returns input unchanged.
func TestNoopSigner_Sign(t *testing.T) {
	signer := NewNoopSigner()

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("test data")},
		{"xml", []byte(`<?xml version="1.0"?><root><child>value</child></root>`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := signer.Sign(tc.data)
			if err != nil {
				t.Errorf("Sign() returned error: %v", err)
			}
			if string(result) != string(tc.data) {
				t.Errorf("Sign() = %q, want %q", result, tc.data)
			}
		})
	}
}

// TestXMLDsigVerifier_Interface verifies the interface contract.
func TestXMLDsigVerifier_Interface(t *testing.T) {
	var _ ports.SignatureVerifier = (*XMLDsigVerifier)(nil)
}

// TestXMLDsigSigner_Interface verifies the interface contract.
func TestXMLDsigSigner_Interface(t *testing.T) {
	var _ ports.MetadataSigner = (*XMLDsigSigner)(nil)
}

// TestXMLDsigVerifier_Verify_InvalidXML verifies error on invalid XML.
func TestXMLDsigVerifier_Verify_InvalidXML(t *testing.T) {
	cert, _ := generateTestCert(t)
	verifier := NewXMLDsigVerifier(cert)

	_, err := verifier.Verify([]byte("not valid xml"))
	if err == nil {
		t.Error("Verify() should return error for invalid XML")
	}
}

// TestXMLDsigVerifier_Verify_EmptyXML verifies error on empty XML.
func TestXMLDsigVerifier_Verify_EmptyXML(t *testing.T) {
	cert, _ := generateTestCert(t)
	verifier := NewXMLDsigVerifier(cert)

	_, err := verifier.Verify([]byte(""))
	if err == nil {
		t.Error("Verify() should return error for empty input")
	}
}

// TestXMLDsigVerifier_Verify_NoSignature verifies error when no signature present.
func TestXMLDsigVerifier_Verify_NoSignature(t *testing.T) {
	cert, _ := generateTestCert(t)
	verifier := NewXMLDsigVerifier(cert)

	xml := []byte(`<?xml version="1.0"?><root><child>value</child></root>`)
	_, err := verifier.Verify(xml)
	if err == nil {
		t.Error("Verify() should return error for unsigned XML")
	}
}

// TestXMLDsigSigner_Sign_Empty verifies error on empty input.
func TestXMLDsigSigner_Sign_Empty(t *testing.T) {
	cert, key := generateTestCert(t)
	signer := NewXMLDsigSigner(key, cert)

	_, err := signer.Sign([]byte(""))
	if err == nil {
		t.Error("Sign() should return error for empty input")
	}
}

// TestXMLDsigSigner_Sign_InvalidXML verifies error on invalid XML.
func TestXMLDsigSigner_Sign_InvalidXML(t *testing.T) {
	cert, key := generateTestCert(t)
	signer := NewXMLDsigSigner(key, cert)

	_, err := signer.Sign([]byte("not valid xml"))
	if err == nil {
		t.Error("Sign() should return error for invalid XML")
	}
}

// TestXMLDsigSignerAndVerifier_Roundtrip verifies sign then verify works.
func TestXMLDsigSignerAndVerifier_Roundtrip(t *testing.T) {
	cert, key := generateTestCert(t)
	signer := NewXMLDsigSigner(key, cert)
	verifier := NewXMLDsigVerifier(cert)

	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root xmlns="urn:test"><child>value</child></root>`)

	signed, err := signer.Sign(xml)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	verified, err := verifier.Verify(signed)
	if err != nil {
		t.Fatalf("Verify() returned error: %v", err)
	}

	// Verified output should contain the original data (may have signature stripped)
	if len(verified) == 0 {
		t.Error("Verify() returned empty result")
	}
}

// TestXMLDsigVerifierWithCerts_MultipleCerts verifies multiple trust anchors work.
func TestXMLDsigVerifierWithCerts_MultipleCerts(t *testing.T) {
	cert1, key1 := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	// Create verifier with both certs
	verifier := NewXMLDsigVerifierWithCerts([]*x509.Certificate{cert1, cert2})

	// Create signer with first cert
	signer := NewXMLDsigSigner(key1, cert1)

	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><root xmlns="urn:test"><child>value</child></root>`)

	signed, err := signer.Sign(xml)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	// Should verify with the first cert
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Errorf("Verify() with multiple certs returned error: %v", err)
	}
}

// TestAlgorithmName verifies algorithm URI to name conversion.
func TestAlgorithmName(t *testing.T) {
	testCases := []struct {
		uri  string
		want string
	}{
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RSA-SHA256"},
		{"http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RSA-SHA1"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ECDSA-SHA256"},
		{"unknown-uri", "unknown-uri"}, // Unknown returns unchanged
	}

	for _, tc := range testCases {
		t.Run(tc.uri, func(t *testing.T) {
			got := algorithmName(tc.uri)
			if got != tc.want {
				t.Errorf("algorithmName(%q) = %q, want %q", tc.uri, got, tc.want)
			}
		})
	}
}
