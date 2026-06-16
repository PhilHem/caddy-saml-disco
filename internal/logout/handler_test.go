package logout

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// TestRawSAMLRequest_RoundTripsPlusBearingPayload guards the redirect-binding
// decode: the SAMLRequest must be read without an extra URL-decode, or a '+' in
// the base64 becomes a space and the decode fails.
func TestRawSAMLRequest_RoundTripsPlusBearingPayload(t *testing.T) {
	xmlIn := []byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_` +
		strings.Repeat("abcDEF0123456789", 16) +
		`" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/saml</saml:Issuer></samlp:LogoutRequest>`)

	encoded, err := domain.EncodeSAMLRequest(xmlIn)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(encoded, "%2B") {
		t.Fatalf("fixture does not exercise the bug: encoded form has no URL-escaped '+'")
	}

	r := httptest.NewRequest("GET", "https://sp.example.com/saml/slo?SAMLRequest="+encoded+"&RelayState=/", nil)

	out, err := domain.DecodeSAMLRequest(rawSAMLRequest(r))
	if err != nil {
		t.Fatalf("decode via rawSAMLRequest: %v", err)
	}
	if string(out) != string(xmlIn) {
		t.Fatalf("round-trip mismatch:\n got %s\nwant %s", out, xmlIn)
	}

	// Reading the value through Query().Get() pre-unescapes it, so the second
	// unescape inside DecodeSAMLRequest corrupts the '+'. This path must fail,
	// which is exactly why rawSAMLRequest reads from RawQuery instead.
	if _, err := domain.DecodeSAMLRequest(r.URL.Query().Get("SAMLRequest")); err == nil {
		t.Fatal("expected the double-decoded path to fail, but it succeeded")
	}
}
