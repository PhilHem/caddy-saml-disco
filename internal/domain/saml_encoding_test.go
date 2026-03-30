//go:build unit

package domain

import (
	"bytes"
	"testing"
)

func TestSAMLRequest_RoundTrip(t *testing.T) {
	// Sample SAML AuthnRequest XML
	originalXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_test123"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>`)

	// Encode
	encoded, err := EncodeSAMLRequest(originalXML)
	if err != nil {
		t.Fatalf("EncodeSAMLRequest failed: %v", err)
	}

	if encoded == "" {
		t.Fatal("encoded string should not be empty")
	}

	// Decode
	decoded, err := DecodeSAMLRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSAMLRequest failed: %v", err)
	}

	// Verify round-trip
	if !bytes.Equal(decoded, originalXML) {
		t.Errorf("round-trip failed:\ngot:  %s\nwant: %s", decoded, originalXML)
	}
}

func TestDecodeSAMLRequest_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: true, // Empty string fails base64 decode then inflate
		},
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "valid base64 but not deflated",
			input:   "SGVsbG8gV29ybGQ=", // "Hello World" in base64
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSAMLRequest(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("DecodeSAMLRequest() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestEncodeSAMLRequest_EmptyInput(t *testing.T) {
	// Empty XML should still encode successfully
	encoded, err := EncodeSAMLRequest([]byte{})
	if err != nil {
		t.Fatalf("EncodeSAMLRequest failed on empty input: %v", err)
	}

	// Should be decodable
	decoded, err := DecodeSAMLRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeSAMLRequest failed: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("expected empty decoded, got %d bytes", len(decoded))
	}
}
