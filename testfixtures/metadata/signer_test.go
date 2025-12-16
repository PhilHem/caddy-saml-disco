//go:build unit

// Package metadata provides a signed metadata generator for testing.
package metadata

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	samldisco "github.com/philiph/caddy-saml-disco"
)

// Phase 1: Basic Structure Tests

func TestNew_ReturnsNonNil(t *testing.T) {
	signer := New(t)
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestSigner_Certificate_ReturnsValidCert(t *testing.T) {
	signer := New(t)
	cert := signer.Certificate()
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if cert.Subject.CommonName == "" {
		t.Error("expected certificate to have CommonName")
	}
}

// Phase 2: Sign Method Tests

func TestSigner_Sign_ReturnsSignedXML(t *testing.T) {
	signer := New(t)
	unsigned := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test.example.com"/>`)

	signed, err := signer.Sign(unsigned)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(signed) == 0 {
		t.Error("expected non-empty signed output")
	}
}

func TestSigner_Sign_ContainsSignatureElement(t *testing.T) {
	signer := New(t)
	unsigned := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test.example.com"/>`)

	signed, err := signer.Sign(unsigned)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// goxmldsig uses ds: prefix for Signature elements
	if !bytes.Contains(signed, []byte("Signature")) {
		t.Errorf("expected signed XML to contain Signature element, got: %s", string(signed))
	}
}

// Phase 3: Integration with XMLDsigVerifier

func loadTestMetadata(t *testing.T, filename string) []byte {
	t.Helper()
	// Navigate from testfixtures/metadata to testdata
	path := filepath.Join("..", "..", "testdata", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to load test metadata %s: %v", filename, err)
	}
	return data
}

func TestSigner_SignedMetadata_VerifiesWithXMLDsigVerifier(t *testing.T) {
	// Arrange
	signer := New(t)
	unsigned := loadTestMetadata(t, "idp-metadata.xml")

	signed, err := signer.Sign(unsigned)
	if err != nil {
		t.Fatalf("failed to sign metadata: %v", err)
	}

	// Create verifier with signer's certificate
	verifier := samldisco.NewXMLDsigVerifier(signer.Certificate())

	// Act
	validated, err := verifier.Verify(signed)

	// Assert
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if len(validated) == 0 {
		t.Error("expected non-empty validated output")
	}
}

func TestSigner_SignedMetadata_FailsWithWrongCert(t *testing.T) {
	// Arrange: Two different signers (different keys)
	signer1 := New(t)
	signer2 := New(t)

	signed, err := signer1.Sign(loadTestMetadata(t, "idp-metadata.xml"))
	if err != nil {
		t.Fatalf("failed to sign metadata: %v", err)
	}

	// Verifier uses signer2's cert (wrong one)
	verifier := samldisco.NewXMLDsigVerifier(signer2.Certificate())

	// Act
	_, err = verifier.Verify(signed)

	// Assert
	if err == nil {
		t.Error("expected verification to fail with mismatched certificate")
	}
}

// Phase 4: Error Cases

func TestSigner_Sign_FailsOnMalformedXML(t *testing.T) {
	signer := New(t)
	malformed := []byte(`<not closed`)

	_, err := signer.Sign(malformed)

	if err == nil {
		t.Error("expected error for malformed XML")
	}
}

func TestSigner_Sign_FailsOnEmptyInput(t *testing.T) {
	signer := New(t)

	_, err := signer.Sign([]byte{})

	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestSigner_Sign_FailsOnWhitespaceOnlyInput(t *testing.T) {
	signer := New(t)

	_, err := signer.Sign([]byte("   \n\t  "))

	if err == nil {
		t.Error("expected error for whitespace-only input")
	}
}

// Phase 5: Aggregate Metadata Support

func TestSigner_Sign_WorksWithAggregateMetadata(t *testing.T) {
	signer := New(t)
	aggregate := loadTestMetadata(t, "aggregate-metadata.xml")

	signed, err := signer.Sign(aggregate)
	if err != nil {
		t.Fatalf("failed to sign aggregate metadata: %v", err)
	}

	// Verify it
	verifier := samldisco.NewXMLDsigVerifier(signer.Certificate())
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Fatalf("verification of signed aggregate failed: %v", err)
	}
}

// Phase 6: Convenience Methods

func TestSigner_GenerateIdPMetadata_CreatesValidSignedMetadata(t *testing.T) {
	signer := New(t)

	signed, err := signer.GenerateIdPMetadata("https://idp.example.com")
	if err != nil {
		t.Fatalf("failed to generate IdP metadata: %v", err)
	}

	// Should contain entityID
	if !bytes.Contains(signed, []byte(`entityID="https://idp.example.com"`)) {
		t.Error("expected signed metadata to contain entityID")
	}

	// Should be verifiable
	verifier := samldisco.NewXMLDsigVerifier(signer.Certificate())
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestSigner_GenerateAggregateMetadata_CreatesSignedAggregate(t *testing.T) {
	signer := New(t)
	entityIDs := []string{"https://idp1.example.com", "https://idp2.example.com"}

	signed, err := signer.GenerateAggregateMetadata(entityIDs)
	if err != nil {
		t.Fatalf("failed to generate aggregate metadata: %v", err)
	}

	// Should contain both entityIDs
	for _, id := range entityIDs {
		if !bytes.Contains(signed, []byte(id)) {
			t.Errorf("expected signed metadata to contain entityID %s", id)
		}
	}

	// Should be verifiable
	verifier := samldisco.NewXMLDsigVerifier(signer.Certificate())
	_, err = verifier.Verify(signed)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}
