//go:build unit

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/request"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// makeLogoutResponseXML builds a minimal SAML 2.0 LogoutResponse XML document.
func makeLogoutResponseXML(issuer, statusCode, inResponseTo string) string {
	inResponseToAttr := ""
	if inResponseTo != "" {
		inResponseToAttr = fmt.Sprintf(` InResponseTo="%s"`, inResponseTo)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_response1"
  Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="%s"/>
  </samlp:Status>
</samlp:LogoutResponse>`, inResponseToAttr, issuer, statusCode)
}

// encodeLogoutResponse base64-encodes a LogoutResponse XML string (redirect binding).
func encodeLogoutResponse(xml string) string {
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// makeTestSAMLService creates a SAMLService backed by an in-memory request store.
func makeTestSAMLService(t *testing.T, logger *zap.Logger) *SAMLService {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	store := request.NewInMemoryRequestStore()
	svc := NewSAMLServiceWithStore("https://sp.example.com", key, cert, store)
	svc.SetLogger(logger)
	return svc
}

// makeTestIdP returns a minimal IdPInfo for use in tests.
func makeTestIdP() *domain.IdPInfo {
	return &domain.IdPInfo{
		EntityID: "https://idp.example.com",
		SSOURL:   "https://idp.example.com/sso",
		SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	}
}

// makeLogoutResponseRequest creates an *http.Request with a SAMLResponse query parameter.
func makeLogoutResponseRequest(samlResponseB64 string) *http.Request {
	u := &url.URL{
		Scheme:   "https",
		Host:     "sp.example.com",
		Path:     "/saml/slo",
		RawQuery: "SAMLResponse=" + url.QueryEscape(samlResponseB64),
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	return req
}

// sloTestURL returns a dummy SLO URL for use in tests.
func sloTestURL() *url.URL {
	u, _ := url.Parse("https://sp.example.com/saml/slo")
	return u
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestHandleLogoutResponse_ValidResponse(t *testing.T) {
	tra.RequireLegacy(t)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	svc := makeTestSAMLService(t, logger)

	xml := makeLogoutResponseXML("https://idp.example.com", samlStatusSuccess, "")
	encoded := encodeLogoutResponse(xml)
	r := makeLogoutResponseRequest(encoded)
	idp := makeTestIdP()

	err := svc.HandleLogoutResponse(r, sloTestURL(), idp)
	if err != nil {
		t.Errorf("HandleLogoutResponse() unexpected error: %v", err)
	}
	if logs.Len() != 0 {
		t.Errorf("expected no warning logs, got %d: %v", logs.Len(), logs.All())
	}
}

func TestHandleLogoutResponse_MissingSAMLResponse(t *testing.T) {
	tra.RequireLegacy(t)

	svc := makeTestSAMLService(t, zap.NewNop())

	req, _ := http.NewRequest(http.MethodGet, "https://sp.example.com/saml/slo", nil)
	err := svc.HandleLogoutResponse(req, sloTestURL(), makeTestIdP())
	if err == nil {
		t.Fatal("expected error for missing SAMLResponse, got nil")
	}
}

func TestHandleLogoutResponse_BadBase64(t *testing.T) {
	tra.RequireLegacy(t)

	svc := makeTestSAMLService(t, zap.NewNop())

	r := makeLogoutResponseRequest("not-valid-base64!!!")
	err := svc.HandleLogoutResponse(r, sloTestURL(), makeTestIdP())
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestHandleLogoutResponse_MalformedXML(t *testing.T) {
	tra.RequireLegacy(t)

	svc := makeTestSAMLService(t, zap.NewNop())

	encoded := encodeLogoutResponse("<this is not valid xml>>>")
	r := makeLogoutResponseRequest(encoded)
	err := svc.HandleLogoutResponse(r, sloTestURL(), makeTestIdP())
	if err == nil {
		t.Fatal("expected error for malformed XML, got nil")
	}
}

func TestHandleLogoutResponse_NonSuccessStatusCode(t *testing.T) {
	tra.RequireLegacy(t)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	svc := makeTestSAMLService(t, logger)

	xml := makeLogoutResponseXML("https://idp.example.com",
		"urn:oasis:names:tc:SAML:2.0:status:Responder", "")
	encoded := encodeLogoutResponse(xml)
	r := makeLogoutResponseRequest(encoded)

	err := svc.HandleLogoutResponse(r, sloTestURL(), makeTestIdP())
	if err == nil {
		t.Fatal("expected error for non-Success StatusCode, got nil")
	}

	warnLogs := logs.FilterMessage("LogoutResponse StatusCode is not Success")
	if warnLogs.Len() == 0 {
		t.Error("expected warning log for non-Success StatusCode")
	}
}

func TestHandleLogoutResponse_MismatchedIssuer(t *testing.T) {
	tra.RequireLegacy(t)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	svc := makeTestSAMLService(t, logger)

	// Issuer does not match idp.EntityID
	xml := makeLogoutResponseXML("https://wrong-idp.example.com", samlStatusSuccess, "")
	encoded := encodeLogoutResponse(xml)
	r := makeLogoutResponseRequest(encoded)

	err := svc.HandleLogoutResponse(r, sloTestURL(), makeTestIdP())
	if err == nil {
		t.Fatal("expected error for mismatched Issuer, got nil")
	}

	warnLogs := logs.FilterMessage("LogoutResponse Issuer does not match expected IdP")
	if warnLogs.Len() == 0 {
		t.Error("expected warning log for Issuer mismatch")
	}
}

func TestHandleLogoutResponse_InResponseToWarning(t *testing.T) {
	tra.RequireLegacy(t)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)
	svc := makeTestSAMLService(t, logger)

	// Valid response but InResponseTo references an ID not in the request store.
	xml := makeLogoutResponseXML("https://idp.example.com", samlStatusSuccess, "unknown-request-id")
	encoded := encodeLogoutResponse(xml)
	r := makeLogoutResponseRequest(encoded)

	// Should succeed (InResponseTo mismatch is a warning, not a hard failure).
	err := svc.HandleLogoutResponse(r, sloTestURL(), makeTestIdP())
	if err != nil {
		t.Errorf("HandleLogoutResponse() unexpected error: %v", err)
	}

	warnLogs := logs.FilterMessage("LogoutResponse InResponseTo not found in pending requests")
	if warnLogs.Len() == 0 {
		t.Error("expected warning log for unknown InResponseTo")
	}
	fields := warnLogs.All()[0].ContextMap()
	if _, ok := fields["in_response_to"]; !ok {
		t.Error("expected in_response_to field in warning log")
	}
}
