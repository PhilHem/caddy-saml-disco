//go:build unit

package caddysamldisco

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/beevik/etree"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// =============================================================================
// Phase 1: Core Interface + NoopVerifier
// =============================================================================

// Cycle 1.1: Verify SignatureVerifier interface exists with required method
func TestSignatureVerifier_Interface(t *testing.T) {
	// This test verifies the interface contract exists
	var _ SignatureVerifier = (*mockSignatureVerifier)(nil)
}

// mockSignatureVerifier is a minimal implementation for interface verification
type mockSignatureVerifier struct{}

func (m *mockSignatureVerifier) Verify(data []byte) ([]byte, error) {
	return nil, nil
}

// Cycle 1.2: Verify NoopVerifier implements interface
func TestNoopVerifier_Interface(t *testing.T) {
	var _ SignatureVerifier = (*NoopVerifier)(nil)
}

// Cycle 1.3: NoopVerifier returns input unchanged
func TestNoopVerifier_Verify_ReturnsInput(t *testing.T) {
	verifier := NewNoopVerifier()
	input := []byte("<metadata>test</metadata>")

	result, err := verifier.Verify(input)
	if err != nil {
		t.Fatalf("Verify() returned error: %v", err)
	}

	if string(result) != string(input) {
		t.Errorf("Verify() = %q, want %q", result, input)
	}
}

// Cycle 1.4: NoopVerifier handles empty/nil input
func TestNoopVerifier_Verify_EmptyInput(t *testing.T) {
	verifier := NewNoopVerifier()

	result, err := verifier.Verify([]byte{})
	if err != nil {
		t.Fatalf("Verify() returned error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Verify() returned %d bytes, want 0", len(result))
	}
}

func TestNoopVerifier_Verify_NilInput(t *testing.T) {
	verifier := NewNoopVerifier()

	result, err := verifier.Verify(nil)
	if err != nil {
		t.Fatalf("Verify() returned error: %v", err)
	}

	if result != nil {
		t.Errorf("Verify(nil) = %v, want nil", result)
	}
}

// Cycle 1.5: ErrCodeSignatureInvalid exists and has correct HTTP status
func TestErrorCode_SignatureInvalid(t *testing.T) {
	if ErrCodeSignatureInvalid.String() != "signature_invalid" {
		t.Errorf("ErrCodeSignatureInvalid.String() = %q, want %q",
			ErrCodeSignatureInvalid.String(), "signature_invalid")
	}

	// Signature errors should return 400 Bad Request
	if ErrCodeSignatureInvalid.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("HTTPStatus() = %d, want %d",
			ErrCodeSignatureInvalid.HTTPStatus(), http.StatusBadRequest)
	}
}

func TestErrorCode_SignatureInvalid_Title(t *testing.T) {
	title := ErrCodeSignatureInvalid.Title()
	if title == "" || title == "Error" {
		t.Errorf("Title() = %q, want a specific title", title)
	}
}

// =============================================================================
// Phase 2: XMLDsigVerifier
// =============================================================================

// loadTestCertFromFile loads a certificate from a PEM file for testing
func loadTestCertFromFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	pemData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert file %s: %v", path, err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// Cycle 2.1: Verify XMLDsigVerifier implements interface
func TestXMLDsigVerifier_Interface(t *testing.T) {
	var _ SignatureVerifier = (*XMLDsigVerifier)(nil)
}

// Cycle 2.2: Constructor accepts certificate
func TestNewXMLDsigVerifier(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")

	verifier := NewXMLDsigVerifier(cert)
	if verifier == nil {
		t.Fatal("NewXMLDsigVerifier() returned nil")
	}
}

// Cycle 2.3: Constructor accepts multiple certificates
func TestNewXMLDsigVerifier_MultipleCerts(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")

	verifier := NewXMLDsigVerifierWithCerts([]*x509.Certificate{cert, cert})
	if verifier == nil {
		t.Fatal("NewXMLDsigVerifierWithCerts() returned nil")
	}
}

// Cycle 2.4: Verify returns error for unsigned metadata (missing signature)
func TestXMLDsigVerifier_Verify_MissingSignature(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifier(cert)

	unsignedXML := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://idp.example.com"/>
</EntitiesDescriptor>`)

	_, err := verifier.Verify(unsignedXML)
	if err == nil {
		t.Error("Verify() should return error for unsigned metadata")
	}
}

// Cycle 2.5: Verify returns error for malformed XML
func TestXMLDsigVerifier_Verify_MalformedXML(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifier(cert)

	malformedXML := []byte(`<not valid xml`)

	_, err := verifier.Verify(malformedXML)
	if err == nil {
		t.Error("Verify() should return error for malformed XML")
	}
}

// Cycle 2.8: Verify returns AppError for verification failures
func TestXMLDsigVerifier_Verify_ReturnsAppError(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifier(cert)

	unsignedXML := []byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`)

	_, err := verifier.Verify(unsignedXML)

	var appErr *AppError
	if !errors.As(err, &appErr) {
		t.Errorf("error should be *AppError, got %T", err)
	}
	if appErr != nil && appErr.Code != ErrCodeSignatureInvalid {
		t.Errorf("error code = %v, want %v", appErr.Code, ErrCodeSignatureInvalid)
	}
}

// Cycle 2.3 additional: LoadSigningCertificates helper function
func TestLoadSigningCertificates(t *testing.T) {
	certs, err := LoadSigningCertificates("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("LoadSigningCertificates() failed: %v", err)
	}

	if len(certs) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestLoadSigningCertificates_NotFound(t *testing.T) {
	_, err := LoadSigningCertificates("testdata/nonexistent.pem")
	if err == nil {
		t.Error("LoadSigningCertificates() should fail for nonexistent file")
	}
}

func TestLoadSigningCertificates_NoCerts(t *testing.T) {
	// Create a temp file with no certificates
	tmpFile, err := os.CreateTemp("", "empty*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("not a certificate")
	tmpFile.Close()

	_, err = LoadSigningCertificates(tmpFile.Name())
	if err == nil {
		t.Error("LoadSigningCertificates() should fail when no certs found")
	}
}

// =============================================================================
// Phase 3: Integration with Metadata Stores
// =============================================================================

// trackingVerifier tracks whether Verify was called
type trackingVerifier struct {
	called bool
}

func (v *trackingVerifier) Verify(data []byte) ([]byte, error) {
	v.called = true
	return data, nil
}

// failingVerifier always returns an error
type failingVerifier struct{}

func (v *failingVerifier) Verify(data []byte) ([]byte, error) {
	return nil, &AppError{
		Code:    ErrCodeSignatureInvalid,
		Message: "test failure",
	}
}

// Cycle 3.1: WithSignatureVerifier option exists
func TestWithSignatureVerifier(t *testing.T) {
	verifier := NewNoopVerifier()
	opt := WithSignatureVerifier(verifier)

	options := &metadataOptions{}
	opt(options)

	if options.signatureVerifier == nil {
		t.Error("signatureVerifier should be set")
	}
}

// Cycle 3.2: FileMetadataStore uses verifier when provided
func TestFileMetadataStore_WithSignatureVerifier(t *testing.T) {
	verifier := &trackingVerifier{}

	store := NewFileMetadataStore("testdata/idp-metadata.xml",
		WithSignatureVerifier(verifier))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !verifier.called {
		t.Error("verifier.Verify() should have been called")
	}
}

// Cycle 3.3: FileMetadataStore fails on invalid signature
func TestFileMetadataStore_WithSignatureVerifier_Invalid(t *testing.T) {
	verifier := &failingVerifier{}

	store := NewFileMetadataStore("testdata/idp-metadata.xml",
		WithSignatureVerifier(verifier))

	err := store.Load()
	if err == nil {
		t.Error("Load() should fail when signature verification fails")
	}
}

// Cycle 3.6: No verification when SignatureVerifier not provided
func TestFileMetadataStore_WithoutSignatureVerifier(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")

	err := store.Load()
	if err != nil {
		t.Fatalf("Load() should succeed without verifier: %v", err)
	}

	// Should load unsigned metadata successfully
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(idps))
	}
}

// Cycle 3.4: URLMetadataStore uses verifier when provided
func TestURLMetadataStore_WithSignatureVerifier(t *testing.T) {
	metadata, _ := os.ReadFile("testdata/idp-metadata.xml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	verifier := &trackingVerifier{}
	store := NewURLMetadataStore(server.URL, time.Hour,
		WithSignatureVerifier(verifier))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !verifier.called {
		t.Error("verifier.Verify() should have been called")
	}
}

// Cycle 3.4: URLMetadataStore fails on invalid signature
func TestURLMetadataStore_WithSignatureVerifier_Invalid(t *testing.T) {
	metadata, _ := os.ReadFile("testdata/idp-metadata.xml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	verifier := &failingVerifier{}
	store := NewURLMetadataStore(server.URL, time.Hour,
		WithSignatureVerifier(verifier))

	err := store.Load()
	if err == nil {
		t.Error("Load() should fail when signature verification fails")
	}
}

// =============================================================================
// Phase 4: Configuration
// =============================================================================

// Cycle 4.1: Config has signature verification fields
func TestConfig_SignatureVerificationFields(t *testing.T) {
	cfg := Config{
		VerifyMetadataSignature: true,
		MetadataSigningCert:     "/path/to/cert.pem",
	}

	if !cfg.VerifyMetadataSignature {
		t.Error("VerifyMetadataSignature should be true")
	}
	if cfg.MetadataSigningCert != "/path/to/cert.pem" {
		t.Errorf("MetadataSigningCert = %q, want /path/to/cert.pem", cfg.MetadataSigningCert)
	}
}

// Cycle 4.2: Validate requires MetadataSigningCert when verification enabled
func TestConfig_Validate_RequiresCertForVerification(t *testing.T) {
	cfg := Config{
		EntityID:                "https://sp.example.com",
		MetadataFile:            "testdata/idp-metadata.xml",
		VerifyMetadataSignature: true,
		// MetadataSigningCert NOT set
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should fail when VerifyMetadataSignature=true but MetadataSigningCert empty")
	}
}

// Cycle 4.2: Validate passes when verification enabled with cert
func TestConfig_Validate_VerificationWithCert(t *testing.T) {
	cfg := Config{
		EntityID:                "https://sp.example.com",
		MetadataFile:            "testdata/idp-metadata.xml",
		VerifyMetadataSignature: true,
		MetadataSigningCert:     "testdata/sp-cert.pem",
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() should pass with valid config: %v", err)
	}
}

// Note: Caddyfile parsing tests are in caddyfile_test.go
// The following test documents what should be tested there:
// - verify_metadata_signature directive (flag)
// - metadata_signing_cert directive (path)

// =============================================================================
// Phase 5: Signature Verification Logging
// =============================================================================

// Cycle 5.1: VerificationDetails struct exists with required fields
func TestVerificationDetails_Fields(t *testing.T) {
	details := VerificationDetails{
		Algorithm:   "RSA-SHA256",
		CertSubject: "CN=Test Signer",
		CertExpiry:  time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
	}

	if details.Algorithm != "RSA-SHA256" {
		t.Errorf("Algorithm = %q, want %q", details.Algorithm, "RSA-SHA256")
	}
	if details.CertSubject != "CN=Test Signer" {
		t.Errorf("CertSubject = %q, want %q", details.CertSubject, "CN=Test Signer")
	}
	if details.CertExpiry.Year() != 2025 {
		t.Errorf("CertExpiry.Year() = %d, want 2025", details.CertExpiry.Year())
	}
}

// Cycle 5.2: algorithmName maps XML DSig URIs to human-readable names
func TestAlgorithmName(t *testing.T) {
	cases := []struct {
		uri  string
		name string
	}{
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RSA-SHA256"},
		{"http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RSA-SHA1"},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "RSA-SHA384"},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RSA-SHA512"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ECDSA-SHA256"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "ECDSA-SHA384"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "ECDSA-SHA512"},
		{"http://unknown.algorithm", "http://unknown.algorithm"}, // unknown returns URI as-is
	}

	for _, tc := range cases {
		got := algorithmName(tc.uri)
		if got != tc.name {
			t.Errorf("algorithmName(%q) = %q, want %q", tc.uri, got, tc.name)
		}
	}
}

// Cycle 5.3: Test extractSignatureAlgorithm extracts algorithm from XML
func TestExtractSignatureAlgorithm(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifier(cert)

	// XML with signature containing algorithm
	xmlWithSig := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    </SignedInfo>
  </Signature>
</EntitiesDescriptor>`)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlWithSig); err != nil {
		t.Fatalf("parse XML: %v", err)
	}

	algo := verifier.extractSignatureAlgorithm(doc.Root())
	if algo != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Errorf("extractSignatureAlgorithm() = %q, want RSA-SHA256 URI", algo)
	}
}

// Cycle 5.3b: Test extractSignatureAlgorithm returns empty for unsigned XML
func TestExtractSignatureAlgorithm_NoSignature(t *testing.T) {
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifier(cert)

	xmlNoSig := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="https://idp.example.com"/>
</EntitiesDescriptor>`)

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlNoSig); err != nil {
		t.Fatalf("parse XML: %v", err)
	}

	algo := verifier.extractSignatureAlgorithm(doc.Root())
	if algo != "" {
		t.Errorf("extractSignatureAlgorithm() = %q, want empty string", algo)
	}
}

// Cycle 5.3c: Constructor with logger exists
func TestNewXMLDsigVerifierWithLogger(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifierWithLogger(cert, logger)

	if verifier == nil {
		t.Fatal("NewXMLDsigVerifierWithLogger() returned nil")
	}
}

// Cycle 5.4: No log on verification failure
func TestXMLDsigVerifier_NoLogOnFailure(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifierWithLogger(cert, logger)

	// Unsigned XML will fail verification
	unsignedXML := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="https://idp.example.com"/>
</EntitiesDescriptor>`)

	_, err := verifier.Verify(unsignedXML)
	if err == nil {
		t.Fatal("Verify() should have failed for unsigned XML")
	}

	// Should NOT log success message on failure
	infoLogs := logs.FilterMessage("metadata signature verified")
	if infoLogs.Len() != 0 {
		t.Errorf("should not log success on failure, got %d logs", infoLogs.Len())
	}
}

// Cycle 5.5: NewXMLDsigVerifierWithCertsAndLogger constructor
func TestNewXMLDsigVerifierWithCertsAndLogger(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	verifier := NewXMLDsigVerifierWithCertsAndLogger([]*x509.Certificate{cert, cert}, logger)

	if verifier == nil {
		t.Fatal("NewXMLDsigVerifierWithCertsAndLogger() returned nil")
	}
	if verifier.logger != logger {
		t.Error("logger not set correctly")
	}
	if len(verifier.certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(verifier.certs))
	}
}

// =============================================================================
// Phase 6: MetadataSigner Interface + NoopSigner
// =============================================================================

// Cycle 6.1: Verify MetadataSigner interface exists with required method
func TestMetadataSigner_Interface(t *testing.T) {
	var _ MetadataSigner = (*mockMetadataSigner)(nil)
}

// mockMetadataSigner is a minimal implementation for interface verification
type mockMetadataSigner struct{}

func (m *mockMetadataSigner) Sign(data []byte) ([]byte, error) {
	return nil, nil
}

// Cycle 6.2: Verify NoopSigner implements interface
func TestNoopSigner_Interface(t *testing.T) {
	var _ MetadataSigner = (*NoopSigner)(nil)
}

// Cycle 6.3: NoopSigner returns input unchanged
func TestNoopSigner_Sign_ReturnsInput(t *testing.T) {
	signer := NewNoopSigner()
	input := []byte("<metadata>test</metadata>")

	result, err := signer.Sign(input)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	if string(result) != string(input) {
		t.Errorf("Sign() = %q, want %q", result, input)
	}
}

// Cycle 6.4: NoopSigner handles empty/nil input
func TestNoopSigner_Sign_EmptyInput(t *testing.T) {
	signer := NewNoopSigner()

	result, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Sign() returned %d bytes, want 0", len(result))
	}
}

func TestNoopSigner_Sign_NilInput(t *testing.T) {
	signer := NewNoopSigner()

	result, err := signer.Sign(nil)
	if err != nil {
		t.Fatalf("Sign() returned error: %v", err)
	}

	if result != nil {
		t.Errorf("Sign(nil) = %v, want nil", result)
	}
}

// =============================================================================
// Phase 7: XMLDsigSigner
// =============================================================================

// Cycle 7.1: Verify XMLDsigSigner implements interface
func TestXMLDsigSigner_Interface(t *testing.T) {
	var _ MetadataSigner = (*XMLDsigSigner)(nil)
}

// Cycle 7.2: Constructor accepts key and certificate
func TestNewXMLDsigSigner(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")

	signer := NewXMLDsigSigner(key, cert)
	if signer == nil {
		t.Fatal("NewXMLDsigSigner() returned nil")
	}
}

// Cycle 7.3: Sign returns signed XML with Signature element
func TestXMLDsigSigner_Sign_ReturnsSignedXML(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	signer := NewXMLDsigSigner(key, cert)

	unsigned := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`)

	signed, err := signer.Sign(unsigned)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Should contain Signature element
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signed); err != nil {
		t.Fatalf("parse signed XML: %v", err)
	}

	root := doc.Root()
	sig := root.FindElement("./Signature")
	if sig == nil {
		sig = root.FindElement(".//[local-name()='Signature']")
	}
	if sig == nil {
		t.Error("signed XML should contain Signature element")
	}
}

// Cycle 7.4: Sign then Verify round-trip succeeds
func TestXMLDsigSigner_Sign_RoundTrip(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")

	signer := NewXMLDsigSigner(key, cert)
	verifier := NewXMLDsigVerifier(cert)

	unsigned := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>`)

	signed, err := signer.Sign(unsigned)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	validated, err := verifier.Verify(signed)
	if err != nil {
		t.Fatalf("Verify() failed after Sign(): %v", err)
	}

	if len(validated) == 0 {
		t.Error("Verify() returned empty validated bytes")
	}
}

// Cycle 7.5: Sign fails on empty input
func TestXMLDsigSigner_Sign_FailsOnEmptyInput(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	signer := NewXMLDsigSigner(key, cert)

	_, err = signer.Sign([]byte{})
	if err == nil {
		t.Error("Sign() should fail on empty input")
	}
}

// Cycle 7.6: Sign fails on malformed XML
func TestXMLDsigSigner_Sign_FailsOnMalformedXML(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	signer := NewXMLDsigSigner(key, cert)

	_, err = signer.Sign([]byte("<not valid xml"))
	if err == nil {
		t.Error("Sign() should fail on malformed XML")
	}
}

// Cycle 7.7: Sign fails on whitespace-only input (no root element)
func TestXMLDsigSigner_Sign_FailsOnWhitespaceOnly(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}
	cert := loadTestCertFromFile(t, "testdata/sp-cert.pem")
	signer := NewXMLDsigSigner(key, cert)

	_, err = signer.Sign([]byte("   \n\t  "))
	if err == nil {
		t.Error("Sign() should fail on whitespace-only input")
	}
}
