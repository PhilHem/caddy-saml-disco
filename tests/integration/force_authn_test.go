//go:build integration

package integration

import (
	"net/url"
	"testing"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/caddy"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/testfixtures/idp"
)

// TestForceAuthnFlow_RedirectsWithFlag tests that forceAuthn is set in AuthnRequest
// when accessing a protected route matching force_authn_paths.
func TestForceAuthnFlow_RedirectsWithFlag(t *testing.T) {
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

	// Test with ForceAuthn enabled
	opts := &domain.AuthnOptions{ForceAuthn: true}
	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/sensitive/data", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	authnReq := decodeAuthnRequest(t, redirectURL)

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

	// Test without ForceAuthn
	opts := &domain.AuthnOptions{ForceAuthn: false}
	redirectURL, err := service.StartAuthWithOptions(idpInfo, acsURL, "/public/page", opts)
	if err != nil {
		t.Fatalf("StartAuthWithOptions failed: %v", err)
	}

	authnReq := decodeAuthnRequest(t, redirectURL)

	if authnReq.ForceAuthn != nil && *authnReq.ForceAuthn {
		t.Error("ForceAuthn should be false or nil when not requested")
	}
}
