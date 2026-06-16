//go:build integration

package integration

import (
	"encoding/xml"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/caddy"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// decodeAuthnRequest is a helper function to decode a SAML AuthnRequest from a redirect URL.
func decodeAuthnRequest(t *testing.T, redirectURL *url.URL) *saml.AuthnRequest {
	t.Helper()

	// Pull the still-URL-encoded SAMLRequest straight from RawQuery. url.Values
	// would unescape it, and DecodeSAMLRequest unescapes again as the first step
	// of the redirect-binding pipeline, so handing it a pre-unescaped value turns
	// '+' into a space and corrupts the base64.
	var samlReqEncoded string
	for _, kv := range strings.Split(redirectURL.RawQuery, "&") {
		if v, ok := strings.CutPrefix(kv, "SAMLRequest="); ok {
			samlReqEncoded = v
			break
		}
	}
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

	inflatedBytes, err := domain.DecodeSAMLRequest(samlReqEncoded)
	if err != nil {
		t.Fatalf("decode SAMLRequest: %v", err)
	}

	var authnReq saml.AuthnRequest
	if err := xml.Unmarshal(inflatedBytes, &authnReq); err != nil {
		t.Fatalf("parse AuthnRequest XML: %v", err)
	}

	return &authnReq
}

// TestAuthnContextFlow_MFARequest tests that RequestedAuthnContext is set in AuthnRequest for MFA.
func TestAuthnContextFlow_MFARequest(t *testing.T) {
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

	// Create SAML service
	service := caddyadapter.NewSAMLService("https://sp.example.com", key, cert)

	// Create IdPInfo from test IdP
	idpInfo := &domain.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Test with MFA context request
	opts := &domain.AuthnOptions{
		RequestedAuthnContext:  []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"},
		AuthnContextComparison: "minimum",
	}

	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/secure", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	if redirectURL == nil {
		t.Fatal("StartAuthWithOptions returned nil URL")
	}

	// Verify AuthnRequest contains MFA context request
	authnReq := decodeAuthnRequest(t, redirectURL)

	if authnReq.RequestedAuthnContext == nil {
		t.Fatal("RequestedAuthnContext should be set")
	}

	if authnReq.RequestedAuthnContext.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract" {
		t.Errorf("AuthnContextClassRef = %q, want %q",
			authnReq.RequestedAuthnContext.AuthnContextClassRef,
			"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract")
	}

	if authnReq.RequestedAuthnContext.Comparison != "minimum" {
		t.Errorf("Comparison = %q, want minimum", authnReq.RequestedAuthnContext.Comparison)
	}

	// Verify RelayState is preserved
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/secure" {
		t.Errorf("RelayState = %q, want %q", relayState, "/secure")
	}
}

// TestAuthnContextFlow_WithoutContext tests that RequestedAuthnContext is not set when not requested.
func TestAuthnContextFlow_WithoutContext(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, _ := session.LoadPrivateKey("../../testdata/sp-key.pem")
	cert, _ := session.LoadCertificate("../../testdata/sp-cert.pem")
	service := caddyadapter.NewSAMLService("https://sp.example.com", key, cert)

	idpInfo := &domain.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Test without AuthnContext
	opts := &domain.AuthnOptions{
		RequestedAuthnContext: []string{}, // empty
	}

	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/public", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	// Verify AuthnRequest does NOT contain RequestedAuthnContext
	authnReq := decodeAuthnRequest(t, redirectURL)

	if authnReq.RequestedAuthnContext != nil {
		t.Error("RequestedAuthnContext should be nil when not requested")
	}
}
