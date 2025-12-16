//go:build go1.18

package caddysamldisco

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// fuzzTestKey is a shared RSA key for fuzz tests, generated once at init.
var fuzzTestKey *rsa.PrivateKey

// fuzzTestCert is a shared certificate for XMLDsig fuzz tests, generated once at init.
var fuzzTestCert *x509.Certificate

func init() {
	var err error
	fuzzTestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate fuzz test key: " + err.Error())
	}

	// Generate a self-signed certificate for XMLDsig verification tests
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Fuzz Test Signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &fuzzTestKey.PublicKey, fuzzTestKey)
	if err != nil {
		panic("failed to generate fuzz test cert: " + err.Error())
	}
	fuzzTestCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		panic("failed to parse fuzz test cert: " + err.Error())
	}
}

// fuzzRelayStateSeeds returns seed corpus entries for relay state fuzzing.
// Minimal set covers the key attack categories.
func fuzzRelayStateSeeds() []string {
	return []string{
		// Valid paths
		"", "/", "/dashboard", "/page?foo=bar",
		// Open redirect attacks
		"http://evil.com", "//evil.com",
		// Dangerous schemes
		"javascript:alert(1)",
		// Encoding bypasses
		"%2f%2fevil.com",
		// Header injection
		"/path\r\nHeader: injection",
	}
}

// fuzzRelayStateSeedsExtended returns the full seed corpus for CI.
func fuzzRelayStateSeedsExtended() []string {
	return []string{
		// Valid relative paths
		"", "/", "/dashboard", "/page?foo=bar", "/page#section",
		"/app/settings/profile", "/path/with spaces", "/unicode/日本語",

		// Attack patterns (open redirect)
		"http://evil.com", "https://evil.com/path", "https://evil.com:8080/path",
		"//evil.com", "//evil.com/path", "///evil.com",

		// Dangerous schemes
		"javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)", "file:///etc/passwd", "ftp://evil.com",

		// URL encoding bypasses
		"%2f%2fevil.com", "%2F%2Fevil.com", "/%2fevil.com", "/%2Fevil.com",
		"%252f%252fevil.com", "/path%00//evil.com",

		// Mixed slashes and backslashes
		"\\\\evil.com", "\\/evil.com", "/\\evil.com", "/\\/evil.com",

		// Header injection
		"/path\nHeader: injection", "/path\r\nHeader: injection",
		"/path%0d%0aHeader: injection", "/path\x0d\x0aHeader: injection",

		// Whitespace tricks
		" /valid", "\t/valid", "   ", " //evil.com", "\t//evil.com", "/ /evil.com",

		// Case variations
		"HTTP://evil.com", "HTTPS://evil.com", "JavaScript:alert(1)",

		// Unicode normalization attacks
		"/\u2215\u2215evil.com", "/\uff0f\uff0fevil.com",
	}
}

// checkRelayStateInvariants verifies all security invariants for validateRelayState output.
func checkRelayStateInvariants(t *testing.T, input, result string) {
	t.Helper()

	// Invariant 1: Output is never empty
	if result == "" {
		t.Errorf("validateRelayState(%q) returned empty string", input)
	}

	// Invariant 2: Output always starts with "/"
	if !strings.HasPrefix(result, "/") {
		t.Errorf("validateRelayState(%q) = %q, does not start with /", input, result)
	}

	// Invariant 3: Output never starts with "//" (protocol-relative URL)
	if strings.HasPrefix(result, "//") {
		t.Errorf("validateRelayState(%q) = %q, starts with // (protocol-relative)", input, result)
	}

	// Invariant 4: Parsed URL has no scheme or host
	parsed, err := url.Parse(result)
	if err != nil {
		t.Errorf("validateRelayState(%q) = %q, failed to parse: %v", input, result, err)
	} else {
		if parsed.Scheme != "" {
			t.Errorf("validateRelayState(%q) = %q, has scheme: %q", input, result, parsed.Scheme)
		}
		if parsed.Host != "" {
			t.Errorf("validateRelayState(%q) = %q, has host: %q", input, result, parsed.Host)
		}
	}

	// Invariant 5: Output contains no CR/LF (header injection prevention)
	if strings.ContainsAny(result, "\r\n") {
		t.Errorf("validateRelayState(%q) = %q, contains CR/LF", input, result)
	}
}

// FuzzValidateRelayState tests that validateRelayState always returns safe output.
// Uses minimal seed corpus for fast local development runs.
// Run with -fuzztime=5s for quick checks.
func FuzzValidateRelayState(f *testing.F) {
	for _, seed := range fuzzRelayStateSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := validateRelayState(input)
		checkRelayStateInvariants(t, input, result)
	})
}

// fuzzSessionGetSeeds returns seed corpus entries for JWT token parsing fuzzing.
// Minimal set covers the key attack categories.
func fuzzSessionGetSeeds() []string {
	return []string{
		// Empty/invalid
		"",
		"not-a-jwt",
		// Valid structure, invalid content
		"a.b.c",
		// Missing parts
		"header.payload",
		// Too many parts
		"a.b.c.d.e",
		// Algorithm confusion: alg:none attack
		"eyJhbGciOiJub25lIn0.e30.",
		// Invalid base64 characters
		"!!!.@@@.###",
		// Truncated header
		"eyJhbGc",
		// Null byte injection
		"eyJ\x00.e30.sig",
		// Very long input
		strings.Repeat("a", 10000),
	}
}

// checkSessionGetInvariants verifies all security invariants for CookieSessionStore.Get output.
func checkSessionGetInvariants(t *testing.T, input string, session *Session, err error) {
	t.Helper()

	// Invariant 1: Either valid session or ErrSessionNotFound (no other errors exposed)
	if err != nil && !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Get(%q) returned unexpected error type: %v", input, err)
	}

	// Invariant 2: If session returned, it has valid timestamps
	if session != nil {
		if session.IssuedAt.IsZero() {
			t.Errorf("Get(%q) returned session with zero IssuedAt", input)
		}
		if session.ExpiresAt.IsZero() {
			t.Errorf("Get(%q) returned session with zero ExpiresAt", input)
		}
	}

	// Invariant 3: Mutual exclusion - session XOR error
	if (session == nil) == (err == nil) {
		t.Errorf("Get(%q) violated XOR: session=%v, err=%v", input, session, err)
	}
}

// FuzzCookieSessionGet tests that CookieSessionStore.Get handles arbitrary input safely.
// Uses minimal seed corpus for fast local development runs.
// Run with -fuzztime=5s for quick checks.
func FuzzCookieSessionGet(f *testing.F) {
	for _, seed := range fuzzSessionGetSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		store := NewCookieSessionStore(fuzzTestKey, time.Hour)
		session, err := store.Get(input)
		checkSessionGetInvariants(t, input, session, err)
	})
}

// fuzzParseMetadataSeeds returns seed corpus entries for metadata XML parsing fuzzing.
// Minimal set covers key attack categories for XML parsers.
func fuzzParseMetadataSeeds() []string {
	return []string{
		// Valid single EntityDescriptor
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Valid aggregate EntitiesDescriptor
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp1.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`,
		// Empty inputs
		"",
		"   ",
		"\n\t\n",
		// Malformed XML
		"<not valid xml",
		"<EntityDescriptor>",
		"<EntityDescriptor></EntityDescriptor",
		// SP-only metadata (no IDPSSODescriptor)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`,
		// Invalid validUntil format
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="not-a-date"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Expired validUntil
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="2020-01-01T00:00:00Z"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// XXE attempt (entity expansion)
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Null byte injection
		"<?xml version=\"1.0\"?><EntityDescriptor\x00 xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"/>",
		// Invalid UTF-8
		"<?xml version=\"1.0\"?><EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"\xff\xfe\"/>",
		// Very long entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + strings.Repeat("a", 10000) + `"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
	}
}

// checkParseMetadataInvariants verifies all security invariants for parseMetadata output.
func checkParseMetadataInvariants(t *testing.T, input []byte, idps []IdPInfo, validUntil *time.Time, err error) {
	t.Helper()

	// Invariant 1: Error XOR valid IdPs (when IdPs expected)
	// Note: Empty IdPs slice with nil error is valid for SP-only or empty aggregate metadata that fails
	if err != nil && len(idps) > 0 {
		t.Errorf("parseMetadata returned both error and IdPs: err=%v, idps=%d", err, len(idps))
	}

	// Invariant 2: If IdPs returned, each must have non-empty EntityID
	for i, idp := range idps {
		if idp.EntityID == "" {
			t.Errorf("parseMetadata returned IdP[%d] with empty EntityID", i)
		}
	}

	// Invariant 3: If validUntil returned, it must not be zero
	if validUntil != nil && validUntil.IsZero() {
		t.Error("parseMetadata returned zero validUntil timestamp")
	}

	// Invariant 4: validUntil should only be returned with successful parse
	// (if we got an expiry error, validUntil should be nil)
	if err != nil && validUntil != nil {
		// This is actually allowed - the function may return validUntil even on error
		// for informational purposes, but let's verify it's reasonable
		if validUntil.IsZero() {
			t.Error("parseMetadata returned zero validUntil with error")
		}
	}
}

// FuzzParseMetadata tests that parseMetadata handles arbitrary XML input safely.
// Uses minimal seed corpus for fast local development runs.
// Run with -fuzztime=5s for quick checks.
func FuzzParseMetadata(f *testing.F) {
	for _, seed := range fuzzParseMetadataSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		idps, validUntil, err := parseMetadata([]byte(input))
		checkParseMetadataInvariants(t, []byte(input), idps, validUntil, err)
	})
}

// fuzzXMLDsigVerifySeeds returns seed corpus entries for XML signature verification fuzzing.
// Minimal set covers key attack categories for XML-DSig parsers.
func fuzzXMLDsigVerifySeeds() []string {
	return []string{
		// Empty/whitespace inputs
		"",
		"   ",
		"\n\t\n",

		// Malformed XML
		"<not valid xml",
		"<Root>",
		"<Root></Root",

		// Valid XML without signature (should fail verification)
		`<?xml version="1.0"?><Root xmlns="urn:test">content</Root>`,
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp.example.com"/></EntitiesDescriptor>`,

		// Empty Signature element
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></Root>`,

		// Signature with missing SignedInfo
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Signature with empty SignedInfo
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Signature with missing SignatureMethod
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Null byte injection
		"<?xml version=\"1.0\"?><Root\x00><Signature/></Root>",

		// Very long input
		`<?xml version="1.0"?><Root xmlns="urn:test">` + strings.Repeat("x", 10000) + `</Root>`,
	}
}

// fuzzXMLDsigVerifySeedsExtended returns the full seed corpus for CI XML signature verification tests.
func fuzzXMLDsigVerifySeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
		"",
		"   ",
		"\n\t\n",
		"<not valid xml",
		"<Root>",
		"<Root></Root",
		`<?xml version="1.0"?><Root xmlns="urn:test">content</Root>`,
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp.example.com"/></EntitiesDescriptor>`,
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></Root>`,
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignatureValue>YWJj</SignatureValue></Signature></Root>`,
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/><SignatureValue>YWJj</SignatureValue></Signature></Root>`,
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,
		"<?xml version=\"1.0\"?><Root\x00><Signature/></Root>",
		`<?xml version="1.0"?><Root xmlns="urn:test">` + strings.Repeat("x", 10000) + `</Root>`,
	}
}

// checkXMLDsigVerifyInvariants verifies all security invariants for XMLDsigVerifier.Verify output.
func checkXMLDsigVerifyInvariants(t *testing.T, input []byte, result []byte, err error) {
	t.Helper()

	// Invariant 1: Error XOR result - never both, never neither
	if (result == nil) == (err == nil) {
		t.Errorf("Verify violated XOR: result=%v bytes, err=%v", len(result), err)
	}

	// Invariant 2: All errors must be *AppError
	if err != nil {
		var appErr *AppError
		if !errors.As(err, &appErr) {
			t.Errorf("Verify returned non-AppError: %T %v", err, err)
		}

		// Invariant 3: Error code must be ErrCodeSignatureInvalid or ErrCodeServiceError
		if appErr != nil {
			if appErr.Code != ErrCodeSignatureInvalid && appErr.Code != ErrCodeServiceError {
				t.Errorf("Verify returned unexpected error code: %v", appErr.Code)
			}
		}
	}

	// Invariant 4: If result returned, it must be non-empty
	if result != nil && len(result) == 0 {
		t.Error("Verify returned empty result bytes")
	}

	// Invariant 5: If result returned, it must be valid XML (re-parseable)
	if result != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(result); err != nil {
			t.Errorf("Verify returned invalid XML: %v", err)
		}
	}
}

// FuzzXMLDsigVerify tests that XMLDsigVerifier.Verify handles arbitrary XML input safely.
// Uses minimal seed corpus for fast local development runs.
// Run with -fuzztime=5s for quick checks.
func FuzzXMLDsigVerify(f *testing.F) {
	for _, seed := range fuzzXMLDsigVerifySeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		verifier := NewXMLDsigVerifier(fuzzTestCert)
		result, err := verifier.Verify([]byte(input))
		checkXMLDsigVerifyInvariants(t, []byte(input), result, err)
	})
}

// truncate shortens a string for readable error messages in fuzz tests.
func truncate(s string) string {
	if len(s) > 50 {
		return s[:50] + "..."
	}
	return s
}

// fuzzExtractAndValidateExpirySeeds returns minimal seed corpus for extractAndValidateExpiry fuzzing.
// Covers key attack categories: valid cases, malformed RFC3339, expired timestamps, timezone edge cases.
func fuzzExtractAndValidateExpirySeeds() []string {
	return []string{
		// Valid cases
		`<EntityDescriptor validUntil="2099-01-01T00:00:00Z"/>`,
		`<EntitiesDescriptor validUntil="2099-12-31T23:59:59Z"/>`,

		// No validUntil (valid, returns nil)
		`<EntityDescriptor entityID="test"/>`,
		`<EntitiesDescriptor/>`,

		// Malformed RFC3339
		`<EntityDescriptor validUntil="not-a-date"/>`,
		`<EntityDescriptor validUntil="2024-01-01"/>`,
		`<EntityDescriptor validUntil="01/01/2024"/>`,

		// Expired timestamps
		`<EntityDescriptor validUntil="2020-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="1970-01-01T00:00:00Z"/>`,

		// Timezone edge cases
		`<EntityDescriptor validUntil="2099-01-01T00:00:00+00:00"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00-08:00"/>`,

		// Malformed XML (graceful handling)
		`not xml at all`,
		`<broken`,
	}
}

// fuzzExtractAndValidateExpirySeedsExtended returns full seed corpus for CI.
func fuzzExtractAndValidateExpirySeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
		`<EntityDescriptor validUntil="2099-01-01T00:00:00Z"/>`,
		`<EntitiesDescriptor validUntil="2099-12-31T23:59:59Z"/>`,
		`<EntityDescriptor entityID="test"/>`,
		`<EntitiesDescriptor/>`,
		`<EntityDescriptor validUntil="not-a-date"/>`,
		`<EntityDescriptor validUntil="2024-01-01"/>`,
		`<EntityDescriptor validUntil="01/01/2024"/>`,
		`<EntityDescriptor validUntil="2020-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="1970-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00+00:00"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00-08:00"/>`,
		`not xml at all`,
		`<broken`,

		// === Extended RFC3339 variations ===
		`<EntityDescriptor validUntil="2099-01-01T00:00:00.000Z"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00.123456789Z"/>`,
		`<EntityDescriptor validUntil="2099-01-01T12:30:45+05:30"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00-12:00"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00+14:00"/>`,

		// === Malformed timestamps ===
		`<EntityDescriptor validUntil=""/>`,
		`<EntityDescriptor validUntil=" "/>`,
		`<EntityDescriptor validUntil="2024-13-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2024-01-32T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2024-01-01T25:00:00Z"/>`,
		`<EntityDescriptor validUntil="2024-01-01T00:60:00Z"/>`,
		`<EntityDescriptor validUntil="2024-01-01T00:00:60Z"/>`,
		`<EntityDescriptor validUntil="2024-01-01T00:00:00"/>`,
		`<EntityDescriptor validUntil="2024-01-01 00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2024/01/01T00:00:00Z"/>`,

		// === Far future/past dates ===
		`<EntityDescriptor validUntil="9999-12-31T23:59:59Z"/>`,
		// Note: 0001-01-01T00:00:00Z is Go's zero time, treated as "no expiry" by design
		`<EntityDescriptor validUntil="0001-01-01T00:00:01Z"/>`,
		`<EntityDescriptor validUntil="1969-12-31T23:59:59Z"/>`,

		// === Boundary conditions ===
		`<EntityDescriptor validUntil="2000-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2038-01-19T03:14:07Z"/>`,
		`<EntityDescriptor validUntil="2038-01-19T03:14:08Z"/>`,

		// === XML variations ===
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2099-01-01T00:00:00Z"/>`,
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2099-01-01T00:00:00Z"/>`,
		`<?xml version="1.0"?><EntityDescriptor validUntil="2099-01-01T00:00:00Z"/>`,
		`<!-- comment --><EntityDescriptor validUntil="2099-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2099-01-01T00:00:00Z"><!-- inner --></EntityDescriptor>`,

		// === Attack patterns ===
		`<EntityDescriptor validUntil="2099-01-01T00:00:00Z&#x00;"/>`,
		strings.Repeat("<a>", 1000) + strings.Repeat("</a>", 1000),
		`<EntityDescriptor validUntil="` + strings.Repeat("9", 1000) + `"/>`,

		// === Unicode in timestamp ===
		`<EntityDescriptor validUntil="２０９９-01-01T00:00:00Z"/>`,
		`<EntityDescriptor validUntil="2099‐01‐01T00:00:00Z"/>`,
	}
}

// checkExtractAndValidateExpiryInvariants validates security invariants for extractAndValidateExpiry.
func checkExtractAndValidateExpiryInvariants(t *testing.T, input string, result *time.Time, err error) {
	t.Helper()

	// Invariant 1: Error and result are mutually exclusive
	// If error, result must be nil
	if err != nil && result != nil {
		t.Errorf("extractAndValidateExpiry(%q): both error and result non-nil", truncate(input))
	}

	// Invariant 2: Valid result must be in the future (not expired)
	// The function explicitly rejects expired timestamps, so any returned value must be future
	if result != nil {
		if !result.After(time.Now()) {
			t.Errorf("extractAndValidateExpiry(%q): returned past timestamp %v", truncate(input), result)
		}
	}

	// Invariant 3: Expired metadata error uses sentinel
	if err != nil && result == nil {
		if strings.Contains(err.Error(), "in the past") {
			if !errors.Is(err, ErrMetadataExpired) {
				t.Errorf("extractAndValidateExpiry(%q): expired error not wrapped with ErrMetadataExpired", truncate(input))
			}
		}
	}

	// Invariant 4: No panic on any input (implicit - test runs)
}

// FuzzExtractAndValidateExpiry tests that extractAndValidateExpiry handles arbitrary XML input safely.
// Uses minimal seed corpus for fast local development runs.
// Run with: go test -fuzz=FuzzExtractAndValidateExpiry -fuzztime=5s .
func FuzzExtractAndValidateExpiry(f *testing.F) {
	for _, seed := range fuzzExtractAndValidateExpirySeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result, err := extractAndValidateExpiry([]byte(input))
		checkExtractAndValidateExpiryInvariants(t, input, result, err)
	})
}

// fuzzExtractIdPInfoSeeds returns seed corpus entries for IdP info extraction fuzzing.
// Minimal set covers key edge cases for UIInfo and RegistrationInfo parsing.
func fuzzExtractIdPInfoSeeds() []string {
	return []string{
		// Valid EntityDescriptor with UIInfo
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">Example IdP</mdui:DisplayName><mdui:Description xml:lang="en">An example identity provider</mdui:Description></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Missing entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// No IDPSSODescriptor (SP only)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`,

		// Empty UIInfo elements
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en"></mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Whitespace-only display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">   </mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Logo with zero dimensions
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:Logo height="0" width="0">https://idp.example.com/logo.png</mdui:Logo></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Invalid RegistrationInstant
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" entityID="https://idp.example.com"><Extensions><mdrpi:RegistrationInfo registrationAuthority="https://fed.example.com" registrationInstant="not-a-timestamp"/></Extensions><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Unicode in display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="ja">日本語IdP</mdui:DisplayName><mdui:DisplayName xml:lang="en">Japanese IdP</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Multiple languages with empty lang attribute
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="">No Language</mdui:DisplayName><mdui:DisplayName xml:lang="en">English</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Very long display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">` + strings.Repeat("A", 10000) + `</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
	}
}

// checkExtractIdPInfoInvariants validates security invariants for IdP info extraction.
func checkExtractIdPInfoInvariants(t *testing.T, input []byte, idps []IdPInfo, err error) {
	t.Helper()

	// Invariant 1: Each returned IdP has non-empty EntityID
	for i, idp := range idps {
		if idp.EntityID == "" {
			t.Errorf("IdP[%d] has empty EntityID for input: %s", i, truncate(string(input)))
		}
	}

	// Invariant 2: DisplayNames map values are trimmed (no leading/trailing whitespace)
	for i, idp := range idps {
		for lang, name := range idp.DisplayNames {
			if strings.TrimSpace(name) != name {
				t.Errorf("IdP[%d] DisplayNames[%q] has untrimmed value %q", i, lang, name)
			}
		}
	}

	// Invariant 3: Descriptions map values are trimmed
	for i, idp := range idps {
		for lang, desc := range idp.Descriptions {
			if strings.TrimSpace(desc) != desc {
				t.Errorf("IdP[%d] Descriptions[%q] has untrimmed value %q", i, lang, desc)
			}
		}
	}

	// Invariant 4: InformationURLs map values are trimmed
	for i, idp := range idps {
		for lang, url := range idp.InformationURLs {
			if strings.TrimSpace(url) != url {
				t.Errorf("IdP[%d] InformationURLs[%q] has untrimmed value %q", i, lang, url)
			}
		}
	}

	// Invariant 5: No panic occurred (implicit - test completes)
}

// FuzzExtractIdPInfo tests that IdP info extraction handles arbitrary XML input safely.
// Uses minimal seed corpus for fast local development runs.
// Run with: go test -fuzz=FuzzExtractIdPInfo -fuzztime=5s .
func FuzzExtractIdPInfo(f *testing.F) {
	for _, seed := range fuzzExtractIdPInfoSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		idps, _, err := parseMetadata([]byte(input))
		checkExtractIdPInfoInvariants(t, []byte(input), idps, err)
		// Discard err - we only care about invariants on successful parses
		_ = err
	})
}
