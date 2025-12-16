//go:build unit

package caddysamldisco

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// loadTestCert loads the test certificate from testdata.
func loadTestCert(t *testing.T) (*testCredentials, error) {
	t.Helper()

	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		return nil, err
	}

	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		return nil, err
	}

	return &testCredentials{key: key, cert: cert}, nil
}

type testCredentials struct {
	key  interface{}
	cert interface{}
}

// TestNewSAMLService verifies constructor creates a valid service.
func TestNewSAMLService(t *testing.T) {
	creds, err := loadTestCert(t)
	if err != nil {
		t.Fatalf("load test credentials: %v", err)
	}

	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")

	service := NewSAMLService("https://sp.example.com", key, cert)

	if service == nil {
		t.Fatal("NewSAMLService() returned nil")
	}
	if service.entityID != "https://sp.example.com" {
		t.Errorf("entityID = %q, want %q", service.entityID, "https://sp.example.com")
	}
	if service.requestStore == nil {
		t.Error("requestStore should be initialized")
	}
	_ = creds // silence unused
}

// Legacy tests for RequestStore (now InMemoryRequestStore).
// These are kept for backward compatibility; see request_test.go for comprehensive tests.

// TestRequestStore_Store verifies Store adds an entry.
func TestRequestStore_Store(t *testing.T) {
	store := NewInMemoryRequestStore()

	err := store.Store("request-123", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	// Verify entry exists via Valid
	if !store.Valid("request-123") {
		t.Error("Valid() should return true for stored request ID")
	}
}

// TestRequestStore_Valid_ReturnsTrueOnce verifies single-use behavior.
func TestRequestStore_Valid_ReturnsTrueOnce(t *testing.T) {
	store := NewInMemoryRequestStore()
	store.Store("request-123", time.Now().Add(10*time.Minute))

	// First call should return true and consume the ID
	if !store.Valid("request-123") {
		t.Error("first Valid() should return true")
	}

	// Second call should return false (already consumed)
	if store.Valid("request-123") {
		t.Error("second Valid() should return false (single-use)")
	}
}

// TestRequestStore_Valid_ReturnsFalseUnknown verifies unknown IDs return false.
func TestRequestStore_Valid_ReturnsFalseUnknown(t *testing.T) {
	store := NewInMemoryRequestStore()

	if store.Valid("unknown-id") {
		t.Error("Valid() should return false for unknown ID")
	}
}

// TestRequestStore_Valid_ReturnsFalseExpired verifies expired IDs return false.
func TestRequestStore_Valid_ReturnsFalseExpired(t *testing.T) {
	store := NewInMemoryRequestStore()

	// Store with immediate expiry
	store.Store("request-123", time.Now().Add(-1*time.Second))

	if store.Valid("request-123") {
		t.Error("Valid() should return false for expired ID")
	}
}

// TestRequestStore_GetAll returns all valid IDs.
func TestRequestStore_GetAll(t *testing.T) {
	store := NewInMemoryRequestStore()
	store.Store("request-1", time.Now().Add(10*time.Minute))
	store.Store("request-2", time.Now().Add(10*time.Minute))
	store.Store("request-expired", time.Now().Add(-1*time.Second))

	ids := store.GetAll()

	if len(ids) != 2 {
		t.Errorf("GetAll() returned %d IDs, want 2 (excluding expired)", len(ids))
	}

	// Verify the IDs are present
	found := make(map[string]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found["request-1"] {
		t.Error("GetAll() missing request-1")
	}
	if !found["request-2"] {
		t.Error("GetAll() missing request-2")
	}
	if found["request-expired"] {
		t.Error("GetAll() should not include expired ID")
	}
}

// TestGenerateSPMetadata_ValidXML verifies metadata is valid XML.
func TestGenerateSPMetadata_ValidXML(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	// Verify it's valid XML by parsing
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(metadataBytes, &ed); err != nil {
		t.Errorf("generated metadata is not valid XML: %v", err)
	}
}

// TestGenerateSPMetadata_IncludesEntityID verifies entity ID is present.
func TestGenerateSPMetadata_IncludesEntityID(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	var ed saml.EntityDescriptor
	xml.Unmarshal(metadataBytes, &ed)

	if ed.EntityID != "https://sp.example.com" {
		t.Errorf("EntityID = %q, want %q", ed.EntityID, "https://sp.example.com")
	}
}

// TestGenerateSPMetadata_IncludesACS verifies ACS endpoint is present.
func TestGenerateSPMetadata_IncludesACS(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	var ed saml.EntityDescriptor
	xml.Unmarshal(metadataBytes, &ed)

	if len(ed.SPSSODescriptors) == 0 {
		t.Fatal("no SPSSODescriptor in metadata")
	}

	spDesc := ed.SPSSODescriptors[0]
	if len(spDesc.AssertionConsumerServices) == 0 {
		t.Fatal("no AssertionConsumerService in metadata")
	}

	acs := spDesc.AssertionConsumerServices[0]
	if acs.Location != "https://sp.example.com/saml/acs" {
		t.Errorf("ACS Location = %q, want %q", acs.Location, "https://sp.example.com/saml/acs")
	}
}

// TestGenerateSPMetadata_IncludesSigningKeyDescriptor verifies signing KeyDescriptor is present.
func TestGenerateSPMetadata_IncludesSigningKeyDescriptor(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	var ed saml.EntityDescriptor
	xml.Unmarshal(metadataBytes, &ed)

	if len(ed.SPSSODescriptors) == 0 {
		t.Fatal("no SPSSODescriptor in metadata")
	}

	spDesc := ed.SPSSODescriptors[0]

	// Verify we have both encryption and signing KeyDescriptors
	var hasEncryption, hasSigning bool
	for _, kd := range spDesc.KeyDescriptors {
		switch kd.Use {
		case "encryption":
			hasEncryption = true
		case "signing":
			hasSigning = true
		}
	}

	if !hasEncryption {
		t.Error("metadata should contain encryption KeyDescriptor")
	}
	if !hasSigning {
		t.Error("metadata should contain signing KeyDescriptor")
	}
}

// TestGenerateSPMetadata_IncludesCertificate verifies certificate is present.
func TestGenerateSPMetadata_IncludesCertificate(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	// Check for certificate in the metadata
	metadataStr := string(metadataBytes)
	if !strings.Contains(metadataStr, "X509Certificate") {
		t.Error("metadata should contain X509Certificate")
	}
}

// createTestIdPInfo creates an IdPInfo for testing.
func createTestIdPInfo() *IdPInfo {
	return &IdPInfo{
		EntityID:    "https://idp.example.com",
		DisplayName: "Test IdP",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  saml.HTTPRedirectBinding,
		Certificates: []string{
			// Base64-encoded test certificate (from testdata/sp-cert.pem for simplicity)
			"MIIBkTCB+wIJAKHBfpega/JVMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRlc3RTUDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMMBlRlc3RTUDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5pNrjEZ0wQs+Jz6JGb6F/d3gJdPM/yWNZKENS3+GJ2wf8Y5MjGN/mLJa8UYO2M2q9G6wZI3wJQYJP8xGMHOF/AgMBAAGjUzBRMB0GA1UdDgQWBBR4NKb5vqO/nKN7jj/l+HePA8gEVTAfBgNVHSMEGDAWgBR4NKb5vqO/nKN7jj/l+HePA8gEVTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA0EAH6j8j2T3aRP7UbMHrjuLmF3hzz7t4qx0HJK7ZyJNxv/PH3cFJ/cLDqbPNMiOvPPZPZJn9T+3RnHBQ3B3jh5vGw==",
		},
	}
}

// TestStartAuth_GeneratesRedirectURL verifies StartAuth returns a valid URL.
func TestStartAuth_GeneratesRedirectURL(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	redirectURL, err := service.StartAuth(idp, acsURL, "")
	if err != nil {
		t.Fatalf("StartAuth() failed: %v", err)
	}

	if redirectURL == nil {
		t.Fatal("StartAuth() returned nil URL")
	}

	// URL should point to IdP SSO endpoint
	if redirectURL.Host != "idp.example.com" {
		t.Errorf("redirect host = %q, want %q", redirectURL.Host, "idp.example.com")
	}

	// URL should contain SAMLRequest parameter
	if redirectURL.Query().Get("SAMLRequest") == "" {
		t.Error("redirect URL should contain SAMLRequest parameter")
	}
}

// TestStartAuth_IncludesRelayState verifies relay state is in the URL.
func TestStartAuth_IncludesRelayState(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	redirectURL, err := service.StartAuth(idp, acsURL, "https://sp.example.com/original-page")
	if err != nil {
		t.Fatalf("StartAuth() failed: %v", err)
	}

	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "https://sp.example.com/original-page" {
		t.Errorf("RelayState = %q, want %q", relayState, "https://sp.example.com/original-page")
	}
}

// TestStartAuth_StoresRequestID verifies request ID is cached.
func TestStartAuth_StoresRequestID(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	_, err := service.StartAuth(idp, acsURL, "")
	if err != nil {
		t.Fatalf("StartAuth() failed: %v", err)
	}

	// Store should have one entry
	ids := service.requestStore.GetAll()
	if len(ids) != 1 {
		t.Errorf("store has %d entries, want 1", len(ids))
	}
}

// TestHandleACS_RejectsEmptyRequest verifies HandleACS errors on empty request.
func TestHandleACS_RejectsEmptyRequest(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Create a request with no SAMLResponse
	req, _ := http.NewRequest("POST", "https://sp.example.com/saml/acs", nil)

	_, err := service.HandleACS(req, acsURL, idp)
	if err == nil {
		t.Error("HandleACS() should fail with no SAMLResponse")
	}
}

// =============================================================================
// Metadata Signing Tests
// =============================================================================

// TestSetMetadataSigner sets the signer on SAMLService.
func TestSetMetadataSigner(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	signer := NewNoopSigner()
	service.SetMetadataSigner(signer)

	// No panic means success - setter worked
}

// TestGenerateSPMetadata_WithSigner verifies metadata is signed when signer is set.
func TestGenerateSPMetadata_WithSigner(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	signer := NewXMLDsigSigner(key, cert)
	service.SetMetadataSigner(signer)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	// Verify metadata contains Signature element
	metadataStr := string(metadataBytes)
	if !strings.Contains(metadataStr, "Signature") {
		t.Error("signed metadata should contain Signature element")
	}
	if !strings.Contains(metadataStr, "SignatureValue") {
		t.Error("signed metadata should contain SignatureValue element")
	}
}

// TestGenerateSPMetadata_WithSigner_RoundTrip verifies signed metadata can be verified.
func TestGenerateSPMetadata_WithSigner_RoundTrip(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	signer := NewXMLDsigSigner(key, cert)
	service.SetMetadataSigner(signer)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	// Verify with XMLDsigVerifier
	verifier := NewXMLDsigVerifier(cert)
	validated, err := verifier.Verify(metadataBytes)
	if err != nil {
		t.Fatalf("Verify() failed on signed metadata: %v", err)
	}

	if len(validated) == 0 {
		t.Error("Verify() returned empty validated bytes")
	}
}

// TestGenerateSPMetadata_WithoutSigner verifies metadata is unsigned by default.
func TestGenerateSPMetadata_WithoutSigner(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	// No signer set

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadataBytes, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	// Verify metadata does NOT contain Signature element
	metadataStr := string(metadataBytes)
	if strings.Contains(metadataStr, "<Signature") {
		t.Error("unsigned metadata should not contain Signature element")
	}
}
