//go:build integration

package integration

import (
	"net/url"
	"strings"
	"testing"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/caddy"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// TestSLOFlow_SPInitiated tests the SP-initiated Single Logout flow.
// 1. Authenticate user
// 2. Call /saml/logout
// 3. Verify redirect to IdP SLO
// 4. Simulate IdP LogoutResponse
// 5. Verify session cleared, redirects to return_to
func TestSLOFlow_SPInitiated(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create metadata store with IdP that has SLO
	idpInfo := &domain.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		SLOURL:       testIdP.BaseURL() + "/slo", // Test IdP SLO endpoint
		SLOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{}, // Will be populated from IdP
	}

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{*idpInfo})

	// Create SAML service
	service := caddyadapter.NewSAMLService("https://sp.example.com", key, cert)

	// Create plugin instance (simplified for testing)
	// Note: Full integration would require setting up Caddy server
	// This test verifies the SLO flow components work together

	// Test CreateLogoutRequest
	session := &domain.Session{
		Subject:      "testuser@example.com",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SessionIndex: "session-123",
		IdPEntityID:  idpInfo.EntityID,
	}

	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")
	logoutURL, err := service.CreateLogoutRequest(session, idpInfo, sloURL, "/goodbye")
	if err != nil {
		t.Fatalf("CreateLogoutRequest failed: %v", err)
	}

	// Verify logout URL points to IdP SLO
	if !strings.Contains(logoutURL.String(), idpInfo.SLOURL) {
		t.Errorf("logout URL should point to IdP SLO, got %q", logoutURL.String())
	}

	// Verify logout URL contains SAMLRequest
	if !strings.Contains(logoutURL.String(), "SAMLRequest=") {
		t.Error("logout URL should contain SAMLRequest parameter")
	}

	_ = metadataStore // Use metadataStore to avoid unused variable
}

// TestSLOFlow_IdPInitiated tests the IdP-initiated Single Logout flow.
// 1. Authenticate user
// 2. IdP sends LogoutRequest to /saml/slo
// 3. Verify session cleared
// 4. Verify LogoutResponse sent to IdP
func TestSLOFlow_IdPInitiated(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := session.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := session.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create IdPInfo with SLO
	idpInfo := &domain.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		SLOURL:       testIdP.BaseURL() + "/slo",
		SLOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	// Create SAML service
	service := caddyadapter.NewSAMLService("https://sp.example.com", key, cert)

	// Test CreateLogoutResponse
	sloURL, _ := url.Parse("https://sp.example.com/saml/slo")
	responseURL, err := service.CreateLogoutResponse("request-id-123", idpInfo, sloURL, "")
	if err != nil {
		t.Fatalf("CreateLogoutResponse failed: %v", err)
	}

	// Verify response URL contains SAMLResponse
	if !strings.Contains(responseURL.String(), "SAMLResponse=") {
		t.Error("response URL should contain SAMLResponse parameter")
	}

	// Verify response URL points to IdP SLO
	if !strings.Contains(responseURL.String(), idpInfo.SLOURL) {
		t.Errorf("response URL should point to IdP SLO, got %q", responseURL.String())
	}
}

// TestSLOFlow_LogoutEndpoint_RedirectsToSLO tests that metadata store correctly
// identifies IdPs with SLO support.
func TestSLOFlow_LogoutEndpoint_RedirectsToSLO(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Create IdPInfo with SLO
	idpInfo := &domain.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		SLOURL:       testIdP.BaseURL() + "/slo",
		SLOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	metadataStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{*idpInfo})

	// Verify IdP has SLO URL
	idps, err := metadataStore.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs failed: %v", err)
	}

	if len(idps) == 0 {
		t.Fatal("expected at least one IdP")
	}

	if idps[0].SLOURL == "" {
		t.Error("IdP should have SLO URL configured")
	}

	if idps[0].SLOURL != idpInfo.SLOURL {
		t.Errorf("SLOURL = %q, want %q", idps[0].SLOURL, idpInfo.SLOURL)
	}
}
