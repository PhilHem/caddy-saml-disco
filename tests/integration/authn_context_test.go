//go:build integration

package integration

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

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

// TestAuthnContextFlow_MFARequest tests that RequestedAuthnContext is set in AuthnRequest for MFA.
func TestAuthnContextFlow_MFARequest(t *testing.T) {
	// Start test IdP
	testIdP := idp.New(t)
	defer testIdP.Close()

	// Load SP credentials
	key, err := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("load SP key: %v", err)
	}
	cert, err := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	if err != nil {
		t.Fatalf("load SP cert: %v", err)
	}

	// Create SAML service
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)

	// Create IdPInfo from test IdP
	idpInfo := &caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Test with MFA context request
	opts := &caddysamldisco.AuthnOptions{
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
	key, _ := caddysamldisco.LoadPrivateKey("../../testdata/sp-key.pem")
	cert, _ := caddysamldisco.LoadCertificate("../../testdata/sp-cert.pem")
	service := caddysamldisco.NewSAMLService("https://sp.example.com", key, cert)

	idpInfo := &caddysamldisco.IdPInfo{
		EntityID:     testIdP.BaseURL(),
		DisplayName:  "Test IdP",
		SSOURL:       testIdP.SSOURL(),
		SSOBinding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{},
	}

	acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

	// Test without AuthnContext
	opts := &caddysamldisco.AuthnOptions{
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



