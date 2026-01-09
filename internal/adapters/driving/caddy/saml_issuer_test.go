//go:build unit

package caddy

import (
	"encoding/base64"
	"testing"
)

// TestExtractResponseIssuer_Valid tests extraction from a valid SAML response.
func TestExtractResponseIssuer_Valid(t *testing.T) {
	// Minimal SAML Response with Issuer
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response123"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(responseXML))

	issuer, err := ExtractResponseIssuer(encoded)
	if err != nil {
		t.Fatalf("ExtractResponseIssuer() error = %v", err)
	}

	if issuer != "https://idp.example.com/saml" {
		t.Errorf("ExtractResponseIssuer() = %q, want %q", issuer, "https://idp.example.com/saml")
	}
}

// TestExtractResponseIssuer_Empty tests error on empty input.
func TestExtractResponseIssuer_Empty(t *testing.T) {
	_, err := ExtractResponseIssuer("")
	if err == nil {
		t.Error("ExtractResponseIssuer() should fail with empty input")
	}
}

// TestExtractResponseIssuer_InvalidBase64 tests error on invalid base64.
func TestExtractResponseIssuer_InvalidBase64(t *testing.T) {
	_, err := ExtractResponseIssuer("not-valid-base64!!!")
	if err == nil {
		t.Error("ExtractResponseIssuer() should fail with invalid base64")
	}
}

// TestExtractResponseIssuer_InvalidXML tests error on invalid XML.
func TestExtractResponseIssuer_InvalidXML(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("<not valid xml"))

	_, err := ExtractResponseIssuer(encoded)
	if err == nil {
		t.Error("ExtractResponseIssuer() should fail with invalid XML")
	}
}

// TestExtractResponseIssuer_NoIssuer tests error when Issuer element is missing.
func TestExtractResponseIssuer_NoIssuer(t *testing.T) {
	// SAML Response without Issuer element
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="_response123"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(responseXML))

	_, err := ExtractResponseIssuer(encoded)
	if err == nil {
		t.Error("ExtractResponseIssuer() should fail when Issuer is missing")
	}
}

// TestExtractResponseIssuer_EmptyIssuer tests error when Issuer value is empty.
func TestExtractResponseIssuer_EmptyIssuer(t *testing.T) {
	// SAML Response with empty Issuer
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response123"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer></saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>`

	encoded := base64.StdEncoding.EncodeToString([]byte(responseXML))

	_, err := ExtractResponseIssuer(encoded)
	if err == nil {
		t.Error("ExtractResponseIssuer() should fail when Issuer is empty")
	}
}
