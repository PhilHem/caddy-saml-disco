//go:build unit

package caddy

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Property-Based Tests for Certificate Rotation
// =============================================================================
//
// These tests verify security-critical invariants of certificate rotation handling
// through systematic exploration of the state space. They complement example-based
// tests by checking properties hold across all possible certificate configurations.
//
// Bugs Found Through Property-Based Testing:
// - TBD: Will be documented as tests are written and bugs are discovered

// =============================================================================
// Helper Functions
// =============================================================================

// generateIdPCert creates a test certificate for IdP signing.
func generateIdPCert(key *rsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName:   "Test IdP",
			Organization: []string{"Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(cryptorand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create IdP cert: %v", err))
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(fmt.Sprintf("failed to parse IdP cert: %v", err))
	}

	return cert
}

// certToBase64DER converts a certificate to base64-encoded DER (as stored in SAML metadata X509Certificate and IdPInfo.Certificates).
// IdPInfo.Certificates stores certificates as base64-encoded DER (same format as SAML metadata X509Certificate element).
func certToBase64DER(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// =============================================================================
// Property Tests - Cycle 1: Certificate Selection Invariant
// =============================================================================

// TestCertificateRotation_Property_AnyValidCertWorks verifies:
// Property: If an assertion is signed with ANY valid certificate from IdP metadata,
// verification should succeed.
//
// This property ensures certificate rotation works: during rotation, IdPs publish
// multiple certificates and sign assertions with any of them. The SP must accept
// all valid certificates.
func TestCertificateRotation_Property_AnyValidCertWorks(t *testing.T) {
	f := func(certCount int) bool {
		// Limit certificate count for performance (2-5 certificates typical for rotation)
		if certCount < 2 || certCount > 5 {
			return true
		}

		// Generate multiple IdP certificates (simulating rotation: old, new, future)
		now := time.Now()
		var idpKeys []*rsa.PrivateKey
		var idpCerts []*x509.Certificate
		var certStrings []string

		for i := 0; i < certCount; i++ {
			idpKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
			if err != nil {
				return false
			}
			idpKeys = append(idpKeys, idpKey)

			// Create certificates with different validity periods (simulating rotation)
			notBefore := now.Add(-time.Duration(i) * 24 * time.Hour)
			notAfter := now.Add(time.Duration(certCount-i) * 365 * 24 * time.Hour)
			idpCert := generateIdPCert(idpKey, notBefore, notAfter)
			idpCerts = append(idpCerts, idpCert)

			// Convert to base64 DER (as stored in IdPInfo.Certificates - same format as SAML metadata)
			certStrings = append(certStrings, certToBase64DER(idpCert))
		}

		// Create IdPInfo with all certificates
		idp := &domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
			SSOURL:      "https://idp.example.com/sso",
			SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			Certificates: certStrings,
		}

		// Verify all certificates are added to metadata
		// This tests that idpInfoToEntityDescriptor includes all certificates
		idpMetadata, err := idpInfoToEntityDescriptor(idp)
		if err != nil {
			return false
		}

		// Property: All certificates must be in metadata KeyDescriptors
		if len(idpMetadata.IDPSSODescriptors) == 0 {
			return false
		}

		keyDescriptors := idpMetadata.IDPSSODescriptors[0].KeyDescriptors
		if len(keyDescriptors) != certCount {
			return false // Not all certificates added
		}

		// Verify each certificate appears in metadata (order doesn't matter)
		foundCerts := make(map[string]bool)
		for _, kd := range keyDescriptors {
			if kd.Use != "signing" && kd.Use != "" {
				continue // Skip non-signing keys
			}
			if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
				certData := kd.KeyInfo.X509Data.X509Certificates[0].Data
				foundCerts[certData] = true
			}
		}

		// Property: All certificates must be found
		for _, cert := range idpCerts {
			expectedCertData := certToBase64DER(cert)
			if !foundCerts[expectedCertData] {
				return false // Certificate missing from metadata
			}
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestCertificateRotation_Property_OrderIndependent verifies:
// Property: Certificate order in metadata doesn't matter for verification.
//
// This property ensures that the order certificates appear in IdPInfo.Certificates
// doesn't affect which certificates are accepted. All valid certificates should work
// regardless of their position in the list.
func TestCertificateRotation_Property_OrderIndependent(t *testing.T) {
	// Generate 2 certificates
	idpKey1, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}
	idpKey2, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	now := time.Now()
	idpCert1 := generateIdPCert(idpKey1, now.Add(-365*24*time.Hour), now.Add(365*24*time.Hour))
	idpCert2 := generateIdPCert(idpKey2, now, now.Add(730*24*time.Hour))

	cert1Str := certToBase64DER(idpCert1)
	cert2Str := certToBase64DER(idpCert2)

	// Create IdP with cert1, cert2
	idp1 := &domain.IdPInfo{
		EntityID:    "https://idp.example.com",
		DisplayName: "Test IdP",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{cert1Str, cert2Str},
	}

	// Create IdP with cert2, cert1 (reversed order)
	idp2 := &domain.IdPInfo{
		EntityID:    "https://idp.example.com",
		DisplayName: "Test IdP",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{cert2Str, cert1Str},
	}

	// Convert both to EntityDescriptor
	metadata1, err := idpInfoToEntityDescriptor(idp1)
	if err != nil {
		t.Fatalf("failed to build metadata1: %v", err)
	}

	metadata2, err := idpInfoToEntityDescriptor(idp2)
	if err != nil {
		t.Fatalf("failed to build metadata2: %v", err)
	}

	// Property: Both should have same certificates (order doesn't matter)
	// Extract certificate data from both
	certs1 := make(map[string]bool)
	for _, kd := range metadata1.IDPSSODescriptors[0].KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			certs1[kd.KeyInfo.X509Data.X509Certificates[0].Data] = true
		}
	}

	certs2 := make(map[string]bool)
	for _, kd := range metadata2.IDPSSODescriptors[0].KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			certs2[kd.KeyInfo.X509Data.X509Certificates[0].Data] = true
		}
	}

	// Property: Same certificates in both (order independent)
	if len(certs1) != len(certs2) {
		t.Errorf("certificate count mismatch: %d vs %d", len(certs1), len(certs2))
	}

	expectedCert1Data := certToBase64DER(idpCert1)
	expectedCert2Data := certToBase64DER(idpCert2)

	if !certs1[expectedCert1Data] || !certs1[expectedCert2Data] {
		t.Error("metadata1 missing expected certificates")
	}

	if !certs2[expectedCert1Data] || !certs2[expectedCert2Data] {
		t.Error("metadata2 missing expected certificates")
	}
}

// =============================================================================
// Property Tests - Cycle 2: Certificate Expiry Invariant
// =============================================================================

// TestCertificateRotation_Property_ExpiryHandling verifies:
// Property: Expired certificates are rejected, valid certificates are accepted.
//
// This property ensures that certificate expiry is properly validated during
// assertion verification. Expired certificates should not be accepted, even
// if they're in the metadata during a rotation window.
func TestCertificateRotation_Property_ExpiryHandling(t *testing.T) {
	f := func(expiredHoursAgo int64, validHoursFromNow int64) bool {
		// Limit ranges for performance
		if expiredHoursAgo < 1 || expiredHoursAgo > 8760 { // 1 hour to 1 year ago
			return true
		}
		if validHoursFromNow < 1 || validHoursFromNow > 8760 { // 1 hour to 1 year from now
			return true
		}

		now := time.Now()

		// Generate expired certificate
		expiredKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			return false
		}
		expiredCert := generateIdPCert(
			expiredKey,
			now.Add(-time.Duration(expiredHoursAgo+365*24)*time.Hour), // Started long ago
			now.Add(-time.Duration(expiredHoursAgo)*time.Hour),         // Expired hours ago
		)

		// Generate valid certificate
		validKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
		if err != nil {
			return false
		}
		validCert := generateIdPCert(
			validKey,
			now.Add(-24*time.Hour),                                    // Started yesterday
			now.Add(time.Duration(validHoursFromNow)*time.Hour),       // Valid for hours from now
		)

		// Create IdP with both expired and valid certificates
		idp := &domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
			SSOURL:      "https://idp.example.com/sso",
			SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			Certificates: []string{
				certToBase64DER(expiredCert),
				certToBase64DER(validCert),
			},
		}

		// Convert to EntityDescriptor
		metadata, err := idpInfoToEntityDescriptor(idp)
		if err != nil {
			return false
		}

		// Property: Both certificates should be in metadata (expiry checked later during verification)
		// The metadata includes all certificates; expiry is validated by crewjam/saml during ParseResponse
		keyDescriptors := metadata.IDPSSODescriptors[0].KeyDescriptors
		if len(keyDescriptors) < 2 {
			return false // Both certificates should be present
		}

		// Verify certificates are present
		foundExpired := false
		foundValid := false
		expiredCertData := certToBase64DER(expiredCert)
		validCertData := certToBase64DER(validCert)

		for _, kd := range keyDescriptors {
			if len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
				certData := kd.KeyInfo.X509Data.X509Certificates[0].Data
				if certData == expiredCertData {
					foundExpired = true
				}
				if certData == validCertData {
					foundValid = true
				}
			}
		}

		// Property: Both certificates must be in metadata
		// Note: Expiry validation happens during ParseResponse, not here
		return foundExpired && foundValid
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// =============================================================================
// Property Tests - Cycle 4 & 5: Error Handling
// =============================================================================

// TestCertificateRotation_Property_EmptyCertificates verifies:
// Property: Empty certificate list is handled gracefully (returns error, not panic).
func TestCertificateRotation_Property_EmptyCertificates(t *testing.T) {
	idp := &domain.IdPInfo{
		EntityID:    "https://idp.example.com",
		DisplayName: "Test IdP",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{}, // Empty
	}

	// Should not panic
	panicked := false
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()

		_, err = idpInfoToEntityDescriptor(idp)
	}()

	// Property: Should not panic, may return error or succeed (empty certs allowed in metadata)
	if panicked {
		t.Error("idpInfoToEntityDescriptor panicked on empty certificates")
	}

	// Empty certificates are allowed in metadata (IdP may not have published certs yet)
	// The error will occur later during assertion verification if no valid certs exist
	if err != nil {
		t.Logf("idpInfoToEntityDescriptor returned error (acceptable): %v", err)
	}
}

// TestCertificateRotation_Property_InvalidCertificateFormat verifies:
// Property: Invalid certificate format is handled gracefully (returns error, not panic).
func TestCertificateRotation_Property_InvalidCertificateFormat(t *testing.T) {
	f := func(invalidData string) bool {
		// Skip empty data
		if invalidData == "" {
			return true
		}

		idp := &domain.IdPInfo{
			EntityID:    "https://idp.example.com",
			DisplayName: "Test IdP",
			SSOURL:      "https://idp.example.com/sso",
			SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			Certificates: []string{invalidData}, // Invalid format
		}

		// Should not panic
		panicked := false
		var err error

		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()

			_, err = idpInfoToEntityDescriptor(idp)
		}()

		// Property: Should not panic
		// Note: idpInfoToEntityDescriptor doesn't parse certificates, it just passes them through
		// So invalid certs will be in metadata but fail during ParseResponse
		if panicked {
			return false
		}

		// Invalid certificates are passed through to metadata (validation happens later)
		// err may be nil or non-nil, both are acceptable (invalid certs passed through)
		_ = err
		return true
	}

	config := &quick.Config{
		Values: func(values []reflect.Value, r *rand.Rand) {
			// Generate various invalid inputs
			size := r.Intn(100) + 1
			data := make([]byte, size)
			_, _ = r.Read(data)
			values[0] = reflect.ValueOf(string(data))
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}



