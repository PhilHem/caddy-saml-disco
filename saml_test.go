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
	if service.requestCache == nil {
		t.Error("requestCache should be initialized")
	}
	_ = creds // silence unused
}

// TestMemoryRequestIDCache_Store verifies Store adds an entry.
func TestMemoryRequestIDCache_Store(t *testing.T) {
	cache := NewMemoryRequestIDCache()

	err := cache.Store("request-123", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	// Verify entry exists via Valid
	if !cache.Valid("request-123") {
		t.Error("Valid() should return true for stored request ID")
	}
}

// TestMemoryRequestIDCache_Valid_ReturnsTrueOnce verifies single-use behavior.
func TestMemoryRequestIDCache_Valid_ReturnsTrueOnce(t *testing.T) {
	cache := NewMemoryRequestIDCache()
	cache.Store("request-123", time.Now().Add(10*time.Minute))

	// First call should return true and consume the ID
	if !cache.Valid("request-123") {
		t.Error("first Valid() should return true")
	}

	// Second call should return false (already consumed)
	if cache.Valid("request-123") {
		t.Error("second Valid() should return false (single-use)")
	}
}

// TestMemoryRequestIDCache_Valid_ReturnsFalseUnknown verifies unknown IDs return false.
func TestMemoryRequestIDCache_Valid_ReturnsFalseUnknown(t *testing.T) {
	cache := NewMemoryRequestIDCache()

	if cache.Valid("unknown-id") {
		t.Error("Valid() should return false for unknown ID")
	}
}

// TestMemoryRequestIDCache_Valid_ReturnsFalseExpired verifies expired IDs return false.
func TestMemoryRequestIDCache_Valid_ReturnsFalseExpired(t *testing.T) {
	cache := NewMemoryRequestIDCache()

	// Store with immediate expiry
	cache.Store("request-123", time.Now().Add(-1*time.Second))

	if cache.Valid("request-123") {
		t.Error("Valid() should return false for expired ID")
	}
}

// TestMemoryRequestIDCache_GetAll returns all valid IDs.
func TestMemoryRequestIDCache_GetAll(t *testing.T) {
	cache := NewMemoryRequestIDCache()
	cache.Store("request-1", time.Now().Add(10*time.Minute))
	cache.Store("request-2", time.Now().Add(10*time.Minute))
	cache.Store("request-expired", time.Now().Add(-1*time.Second))

	ids := cache.GetAll()

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

	// Cache should have one entry
	ids := service.requestCache.GetAll()
	if len(ids) != 1 {
		t.Errorf("cache has %d entries, want 1", len(ids))
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
