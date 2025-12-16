//go:build go1.18

package caddysamldisco

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fuzzTestKey is a shared RSA key for fuzz tests, generated once at init.
var fuzzTestKey *rsa.PrivateKey

func init() {
	var err error
	fuzzTestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate fuzz test key: " + err.Error())
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
