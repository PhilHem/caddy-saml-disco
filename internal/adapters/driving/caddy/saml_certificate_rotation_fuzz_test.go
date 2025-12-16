//go:build unit

package caddy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// FuzzParseIdPCertificates fuzzes certificate parsing from IdPInfo.Certificates.
// Property: Should never panic, always return error or succeed gracefully.
//
// This test verifies robust error handling for malformed certificate data:
// - Malformed base64
// - Invalid PEM format
// - Truncated certificates
// - Oversized inputs
// - Invalid characters
func FuzzParseIdPCertificates(f *testing.F) {
	// Seed corpus: valid and invalid certificate formats
	seeds := []string{
		"",                                    // Empty
		"invalid",                             // Invalid base64
		"SGVsbG8gV29ybGQ=",                    // Valid base64 but not a certificate
		"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", // Base64 of "-----BEGIN CERTIFICATE-----"
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, certData string) {
		// Generate SP keys for service creation
		spKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Skipf("failed to generate SP key: %v", err)
		}

		spCertTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Test SP",
				Organization: []string{"Test"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		spCertDER, err := x509.CreateCertificate(rand.Reader, &spCertTemplate, &spCertTemplate, &spKey.PublicKey, spKey)
		if err != nil {
			t.Skipf("failed to create SP cert: %v", err)
		}

		spCert, err := x509.ParseCertificate(spCertDER)
		if err != nil {
			t.Skipf("failed to parse SP cert: %v", err)
		}

		// Create IdPInfo with fuzzed certificate data
		idp := &domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
			SSOURL:      "https://idp.example.com/sso",
			SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			Certificates: []string{certData}, // Fuzzed certificate data
		}

		// Create SAML service
		service := NewSAMLService("https://sp.example.com", spKey, spCert)

		// Property: Should never panic
		panicked := false
		var authErr error

		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()

			// Test idpInfoToEntityDescriptor (called internally by StartAuth)
			acsURL, _ := url.Parse("https://sp.example.com/saml/acs")
			_, authErr = service.StartAuth(idp, acsURL, "/protected")
		}()

		// Property: Must not panic
		if panicked {
			t.Errorf("panicked on certificate data: %q", truncateString(certData, 100))
		}

		// Property: Should return error for invalid data, or succeed for valid data
		// Both are acceptable - the key property is no panic
		if authErr != nil {
			// Expected for malformed certificate data
			return
		}

		// If no error, data might be valid (unlikely with fuzzed input, but possible)
		// This is acceptable - the property is that we don't panic
	})
}

// FuzzHandleACS_CertificateRotation fuzzes HandleACS with various certificate configurations.
// Property: Should never panic, always return error or success.
func FuzzHandleACS_CertificateRotation(f *testing.F) {
	// Seed corpus
	seeds := []struct {
		certCount int
		certData  string
	}{
		{0, ""},                    // Empty
		{1, "valid-cert"},          // Single cert
		{2, "cert1"},               // Multiple certs
		{5, "cert"},                // Many certs
		{10, "cert"},               // Very many certs
	}

	for _, seed := range seeds {
		f.Add(seed.certCount, seed.certData)
	}

	f.Fuzz(func(t *testing.T, certCount int, certData string) {
		// Limit certificate count for performance
		if certCount < 0 || certCount > 20 {
			return
		}

		// Limit cert data size
		if len(certData) > 10000 {
			return
		}

		// Generate SP keys
		spKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Skipf("failed to generate SP key: %v", err)
		}

		spCertTemplate := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName:   "Test SP",
				Organization: []string{"Test"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		spCertDER, err := x509.CreateCertificate(rand.Reader, &spCertTemplate, &spCertTemplate, &spKey.PublicKey, spKey)
		if err != nil {
			t.Skipf("failed to create SP cert: %v", err)
		}

		spCert, err := x509.ParseCertificate(spCertDER)
		if err != nil {
			t.Skipf("failed to parse SP cert: %v", err)
		}

		// Create IdPInfo with fuzzed certificate count and data
		certificates := make([]string, certCount)
		for i := 0; i < certCount; i++ {
			certificates[i] = fmt.Sprintf("%s-%d", certData, i)
		}

		idp := &domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
			SSOURL:      "https://idp.example.com/sso",
			SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			Certificates: certificates,
		}

		service := NewSAMLService("https://sp.example.com", spKey, spCert)
		acsURL, _ := url.Parse("https://sp.example.com/saml/acs")

		// Create request with invalid SAMLResponse (will fail verification, but tests cert handling)
		req, _ := http.NewRequest("POST", "https://sp.example.com/saml/acs", nil)
		req.Form = make(url.Values)
		req.Form.Set("SAMLResponse", "invalid-response")

		// Property: Should never panic
		panicked := false
		var handleErr error

		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()

			_, handleErr = service.HandleACS(req, acsURL, idp)
		}()

		// Property: Must not panic
		if panicked {
			t.Errorf("panicked on certificate count %d with data %q", certCount, truncateString(certData, 50))
		}

		// Property: Should return error for invalid response (expected)
		// The key property is no panic, regardless of error
		if handleErr != nil {
			// Expected for invalid SAML response
			return
		}

		// If no error, response was valid (unlikely with fuzzed input)
		// This is acceptable - the property is that we don't panic
	})
}

// truncateString truncates a string to maxLen characters for error messages.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
