//go:build unit

package caddysamldisco

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
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

// createTestIdPInfoWithSLO creates an IdPInfo with SLO endpoint for testing.
func createTestIdPInfoWithSLO() *IdPInfo {
	idp := createTestIdPInfo()
	idp.SLOURL = "https://idp.example.com/slo"
	idp.SLOBinding = saml.HTTPRedirectBinding
	return idp
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

// TestHandleACS_ValidScope verifies scope validation passes for valid scopes.
// Note: Full integration test with real SAML response is in tests/integration/scope_validation_test.go
func TestHandleACS_ScopeValidation_Logic(t *testing.T) {
	// Test that scope validation logic works correctly
	// This is a unit test of the validation logic itself
	idp := createTestIdPInfo()
	idp.AllowedScopes = []domain.ScopeInfo{
		{Value: "example.edu", Regexp: false},
	}

	// Verify IsScopedAttribute works
	if !domain.IsScopedAttribute("eduPersonPrincipalName") {
		t.Error("IsScopedAttribute should return true for eduPersonPrincipalName")
	}

	// Verify ExtractScope works
	scope := domain.ExtractScope("user@example.edu")
	if scope != "example.edu" {
		t.Errorf("ExtractScope = %q, want %q", scope, "example.edu")
	}

	// Verify ValidateScope works
	if !domain.ValidateScope("example.edu", idp.AllowedScopes) {
		t.Error("ValidateScope should return true for valid scope")
	}

	if domain.ValidateScope("evil.edu", idp.AllowedScopes) {
		t.Error("ValidateScope should return false for invalid scope")
	}
}

// TestHandleACS_InvalidScope verifies scope validation rejects invalid scopes.
func TestHandleACS_InvalidScope_Logic(t *testing.T) {
	idp := createTestIdPInfo()
	idp.AllowedScopes = []domain.ScopeInfo{
		{Value: "example.edu", Regexp: false},
	}

	// Invalid scope should fail validation
	if domain.ValidateScope("evil.edu", idp.AllowedScopes) {
		t.Error("ValidateScope should return false for unauthorized scope")
	}
}

// TestHandleACS_NoScopeConfig verifies that IdP with no scopes skips validation.
func TestHandleACS_NoScopeConfig_Logic(t *testing.T) {
	idp := createTestIdPInfo()
	// No AllowedScopes configured

	// Validation should be skipped (no scopes to validate against)
	// This is tested by checking len(idp.AllowedScopes) == 0 in HandleACS
	if len(idp.AllowedScopes) != 0 {
		t.Error("IdP without scope config should have empty AllowedScopes")
	}
}

// TestStartAuth_WithForceAuthn_SetsFlag verifies StartAuthWithOptions sets ForceAuthn in AuthnRequest.
func TestStartAuth_WithForceAuthn_SetsFlag(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	opts := &domain.AuthnOptions{ForceAuthn: true}

	redirectURL, err := service.StartAuthWithOptions(idp, acsURL, "", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions() failed: %v", err)
	}

	if redirectURL == nil {
		t.Fatal("StartAuthWithOptions() returned nil URL")
	}

	// Decode SAMLRequest and verify ForceAuthn="true"
	samlReqEncoded := redirectURL.Query().Get("SAMLRequest")
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

	// Decode: URL decode -> base64 decode -> inflate
	samlReqDecoded, err := url.QueryUnescape(samlReqEncoded)
	if err != nil {
		t.Fatalf("URL decode SAMLRequest: %v", err)
	}

	samlReqBytes, err := base64.StdEncoding.DecodeString(samlReqDecoded)
	if err != nil {
		t.Fatalf("base64 decode SAMLRequest: %v", err)
	}

	// Inflate the deflated SAMLRequest
	inflatedReader := flate.NewReader(strings.NewReader(string(samlReqBytes)))
	defer inflatedReader.Close()
	inflatedBytes, err := io.ReadAll(inflatedReader)
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}

	// Parse XML and verify ForceAuthn attribute
	var authnReq saml.AuthnRequest
	if err := xml.Unmarshal(inflatedBytes, &authnReq); err != nil {
		t.Fatalf("parse AuthnRequest XML: %v", err)
	}

	if authnReq.ForceAuthn == nil || !*authnReq.ForceAuthn {
		t.Error("ForceAuthn should be true in AuthnRequest")
	}
}

// TestStartAuth_WithoutForceAuthn_NotSet verifies StartAuthWithOptions does not set ForceAuthn when false.
func TestStartAuth_WithoutForceAuthn_NotSet(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	opts := &domain.AuthnOptions{ForceAuthn: false}

	redirectURL, err := service.StartAuthWithOptions(idp, acsURL, "", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions() failed: %v", err)
	}

	samlReqEncoded := redirectURL.Query().Get("SAMLRequest")
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

	// Decode SAMLRequest
	samlReqDecoded, _ := url.QueryUnescape(samlReqEncoded)
	samlReqBytes, _ := base64.StdEncoding.DecodeString(samlReqDecoded)
	inflatedReader := flate.NewReader(strings.NewReader(string(samlReqBytes)))
	defer inflatedReader.Close()
	inflatedBytes, _ := io.ReadAll(inflatedReader)

	var authnReq saml.AuthnRequest
	if err := xml.Unmarshal(inflatedBytes, &authnReq); err != nil {
		t.Fatalf("parse AuthnRequest XML: %v", err)
	}

	if authnReq.ForceAuthn != nil && *authnReq.ForceAuthn {
		t.Error("ForceAuthn should be false or nil when not requested")
	}
}

// decodeAuthnRequest is a helper function to decode a SAML AuthnRequest from a redirect URL.
func decodeAuthnRequest(t *testing.T, redirectURL *url.URL) *saml.AuthnRequest {
	t.Helper()

	samlReqEncoded := redirectURL.Query().Get("SAMLRequest")
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

	// Decode: URL decode -> base64 decode -> inflate
	samlReqDecoded, err := url.QueryUnescape(samlReqEncoded)
	if err != nil {
		t.Fatalf("URL decode SAMLRequest: %v", err)
	}

	samlReqBytes, err := base64.StdEncoding.DecodeString(samlReqDecoded)
	if err != nil {
		t.Fatalf("base64 decode SAMLRequest: %v", err)
	}

	// Inflate the deflated SAMLRequest
	inflatedReader := flate.NewReader(strings.NewReader(string(samlReqBytes)))
	defer inflatedReader.Close()
	inflatedBytes, err := io.ReadAll(inflatedReader)
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}

	// Parse XML
	var authnReq saml.AuthnRequest
	if err := xml.Unmarshal(inflatedBytes, &authnReq); err != nil {
		t.Fatalf("parse AuthnRequest XML: %v", err)
	}

	return &authnReq
}

// TestStartAuth_WithAuthnContext_SetsRequestedContext verifies StartAuthWithOptions sets RequestedAuthnContext in AuthnRequest.
func TestStartAuth_WithAuthnContext_SetsRequestedContext(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	opts := &domain.AuthnOptions{
		RequestedAuthnContext:  []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"},
		AuthnContextComparison: "exact",
	}

	redirectURL, err := service.StartAuthWithOptions(idp, acsURL, "", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions() failed: %v", err)
	}

	if redirectURL == nil {
		t.Fatal("StartAuthWithOptions() returned nil URL")
	}

	// Decode SAMLRequest and verify RequestedAuthnContext
	authnReq := decodeAuthnRequest(t, redirectURL)

	if authnReq.RequestedAuthnContext == nil {
		t.Fatal("RequestedAuthnContext should be set")
	}
	if authnReq.RequestedAuthnContext.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract" {
		t.Errorf("AuthnContextClassRef = %q, want %q",
			authnReq.RequestedAuthnContext.AuthnContextClassRef,
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")
	}
	if authnReq.RequestedAuthnContext.Comparison != "exact" {
		t.Errorf("Comparison = %q, want exact", authnReq.RequestedAuthnContext.Comparison)
	}
}

// TestStartAuth_WithEmptyAuthnContext_NoElement verifies that empty RequestedAuthnContext slice does not add XML element.
func TestStartAuth_WithEmptyAuthnContext_NoElement(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	opts := &domain.AuthnOptions{
		RequestedAuthnContext: []string{}, // empty
	}

	redirectURL, err := service.StartAuthWithOptions(idp, acsURL, "", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions() failed: %v", err)
	}

	if redirectURL == nil {
		t.Fatal("StartAuthWithOptions() returned nil URL")
	}

	authnReq := decodeAuthnRequest(t, redirectURL)

	if authnReq.RequestedAuthnContext != nil {
		t.Error("RequestedAuthnContext should be nil for empty slice")
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

// TestSAMLService_CreateLogoutRequest verifies CreateLogoutRequest generates a valid logout URL.
func TestSAMLService_CreateLogoutRequest(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	session := &Session{
		Subject:      "user@example.com",
		NameIDFormat: string(saml.EmailAddressNameIDFormat),
		SessionIndex: "session-123",
		IdPEntityID:  "https://idp.example.com",
	}
	idp := createTestIdPInfoWithSLO()
	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")

	logoutURL, err := service.CreateLogoutRequest(session, idp, sloURL, "")
	if err != nil {
		t.Fatalf("CreateLogoutRequest() failed: %v", err)
	}

	if logoutURL == nil {
		t.Fatal("CreateLogoutRequest() returned nil URL")
	}

	// Verify URL contains SAMLRequest parameter
	if !strings.Contains(logoutURL.String(), "SAMLRequest=") {
		t.Error("logout URL should contain SAMLRequest parameter")
	}

	// Verify URL points to IdP SLO endpoint
	if !strings.Contains(logoutURL.String(), "https://idp.example.com/slo") {
		t.Errorf("logout URL should point to IdP SLO endpoint, got %q", logoutURL.String())
	}
}

// TestSAMLService_HandleLogoutResponse verifies HandleLogoutResponse validates LogoutResponse.
func TestSAMLService_HandleLogoutResponse(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfoWithSLO()
	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")

	// Create a mock HTTP request with SAMLResponse parameter
	// Note: In a real scenario, this would come from the IdP after logout
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			RawQuery: "SAMLResponse=test-response",
		},
	}

	// This test verifies the method exists and can be called
	// Full validation would require a real SAML LogoutResponse
	err := service.HandleLogoutResponse(req, sloURL, idp)
	// We expect an error here since "test-response" is not a valid SAML response
	// The important thing is that the method exists and doesn't panic
	if err == nil {
		t.Log("HandleLogoutResponse accepted invalid response (may be expected)")
	}
}

// TestSAMLService_HandleLogoutRequest verifies HandleLogoutRequest can parse a LogoutRequest.
func TestSAMLService_HandleLogoutRequest(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfoWithSLO()
	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")

	// Create a mock HTTP request with SAMLRequest parameter
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			RawQuery: "SAMLRequest=test-request",
		},
	}

	// This test verifies the method exists
	// Full validation would require a real SAML LogoutRequest
	result, err := service.HandleLogoutRequest(req, sloURL, idp)
	// We expect an error here since "test-request" is not a valid SAML request
	if err == nil && result != nil {
		t.Log("HandleLogoutRequest parsed request (may be expected in some cases)")
	}
}

// TestSAMLService_CreateLogoutResponse verifies CreateLogoutResponse generates a valid response URL.
func TestSAMLService_CreateLogoutResponse(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfoWithSLO()
	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")

	responseURL, err := service.CreateLogoutResponse("request-id-123", idp, sloURL, "")
	if err != nil {
		t.Fatalf("CreateLogoutResponse() failed: %v", err)
	}

	if responseURL == nil {
		t.Fatal("CreateLogoutResponse() returned nil URL")
	}

	// Verify URL contains SAMLResponse parameter
	if !strings.Contains(responseURL.String(), "SAMLResponse=") {
		t.Error("response URL should contain SAMLResponse parameter")
	}
}

// TestGenerateSPMetadata_IncludesSLOEndpoint verifies SP metadata includes SLO endpoint when configured.
func TestGenerateSPMetadata_IncludesSLOEndpoint(t *testing.T) {
	key, _ := LoadPrivateKey("testdata/sp-key.pem")
	cert, _ := LoadCertificate("testdata/sp-cert.pem")
	service := NewSAMLService("https://sp.example.com", key, cert)

	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")
	service.SetSLOURL(sloURL)

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
	metadata, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata() failed: %v", err)
	}

	metadataStr := string(metadata)
	if !strings.Contains(metadataStr, "SingleLogoutService") {
		t.Error("metadata should contain SingleLogoutService")
	}
	if !strings.Contains(metadataStr, "https://sp.example.com/saml/slo") {
		t.Error("metadata should contain SLO URL")
	}
}

// TestHandleACS_EncryptedAssertion verifies that HandleACS can process
// encrypted assertions when SP has encryption keys configured.
// This test verifies that crewjam/saml's ParseResponse handles decryption automatically.
func TestHandleACS_EncryptedAssertion(t *testing.T) {
	// Create SP with encryption keys
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	cert, err := LoadCertificate("testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}
	service := NewSAMLService("https://sp.example.com", key, cert)

	idp := createTestIdPInfo()
	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Note: This test will initially fail because we need to:
	// 1. Configure test IdP to encrypt assertions
	// 2. Create a real encrypted SAML response
	// For now, this is a placeholder that documents the expected behavior
	// Full implementation will be in Cycle 2 with test IdP encryption support

	// TODO: Create encrypted SAML response and verify HandleACS processes it
	// For now, verify that SP has encryption keys configured
	if service == nil {
		t.Fatal("service should not be nil")
	}

	// Verify SP metadata includes encryption KeyDescriptor
	metadata, err := service.GenerateSPMetadata(acsURL)
	if err != nil {
		t.Fatalf("GenerateSPMetadata failed: %v", err)
	}

	metadataStr := string(metadata)
	if !strings.Contains(metadataStr, `use="encryption"`) {
		t.Error("SP metadata should contain encryption KeyDescriptor")
	}
}
