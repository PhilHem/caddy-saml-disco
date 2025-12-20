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

// TestForceAuthnFlow_RedirectsWithFlag tests that forceAuthn is set in AuthnRequest
// when accessing a protected route matching force_authn_paths.
func TestForceAuthnFlow_RedirectsWithFlag(t *testing.T) {
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

	// Test with ForceAuthn enabled
	opts := &caddysamldisco.AuthnOptions{ForceAuthn: true}
	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/sensitive/data", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	// Verify redirect URL contains SAMLRequest
	samlReqEncoded := redirectURL.Query().Get("SAMLRequest")
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

	// Decode SAMLRequest: URL decode -> base64 decode -> inflate
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

	// Verify RelayState is preserved
	relayState := redirectURL.Query().Get("RelayState")
	if relayState != "/sensitive/data" {
		t.Errorf("RelayState = %q, want %q", relayState, "/sensitive/data")
	}
}

// TestForceAuthnFlow_WithoutFlag tests that ForceAuthn is not set when not requested.
func TestForceAuthnFlow_WithoutFlag(t *testing.T) {
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

	// Test without ForceAuthn
	opts := &caddysamldisco.AuthnOptions{ForceAuthn: false}
	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/public/page", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	// Decode SAMLRequest
	samlReqEncoded := redirectURL.Query().Get("SAMLRequest")
	if samlReqEncoded == "" {
		t.Fatal("redirect URL should contain SAMLRequest parameter")
	}

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






