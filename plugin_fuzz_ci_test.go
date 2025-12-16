//go:build fuzz_extended

package caddysamldisco

import (
	"strings"
	"testing"
	"time"
)

// FuzzValidateRelayStateExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzValidateRelayStateExtended -fuzztime=60s .
func FuzzValidateRelayStateExtended(f *testing.F) {
	for _, seed := range fuzzRelayStateSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := validateRelayState(input)
		checkRelayStateInvariants(t, input, result)
	})
}

// fuzzSessionGetSeedsExtended returns the full seed corpus for CI JWT parsing tests.
func fuzzSessionGetSeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
		"",
		"not-a-jwt",
		"a.b.c",
		"header.payload",
		"a.b.c.d.e",
		"eyJhbGciOiJub25lIn0.e30.",
		"!!!.@@@.###",
		"eyJhbGc",
		"eyJ\x00.e30.sig",
		strings.Repeat("a", 10000),

		// === Algorithm confusion attacks ===
		// HS256 header (symmetric key confusion)
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ",
		// HS384 header
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.signature",
		// HS512 header
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.signature",
		// ES256 header (ECDSA)
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",
		// PS256 header (RSA-PSS)
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",

		// === Encoding variations ===
		// URL-safe base64 vs standard
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
		// With padding
		"eyJhbGciOiJSUzI1NiJ9==.eyJzdWIiOiJ0ZXN0In0==.c2ln==",
		// Mixed padding
		"eyJhbGciOiJSUzI1NiJ9=.eyJzdWIiOiJ0ZXN0In0.sig",
		// Double-encoded
		"ZXlKaGJHY2lPaUp1YjI1bEluMC5lMzAu",

		// === Boundary conditions ===
		// Single character parts
		"a.b.c",
		// Empty parts
		"...",
		".payload.signature",
		"header..signature",
		"header.payload.",
		// Very long header
		strings.Repeat("eyJ", 5000) + "." + "e30." + "sig",
		// Very long payload
		"eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("eyJ", 5000) + ".sig",
		// Very long signature
		"eyJhbGciOiJSUzI1NiJ9.e30." + strings.Repeat("a", 10000),

		// === Null byte and control character injection ===
		"eyJhbGciOiJSUzI1NiJ9\x00.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.\x00e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30.\x00sig",
		"eyJhbGci\x00OiJSUzI1NiJ9.e30.sig",
		// Newline injection
		"eyJhbGciOiJSUzI1NiJ9\n.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9\r\n.e30.sig",

		// === Unicode attacks ===
		// Unicode null
		"eyJhbGciOiJSUzI1NiJ9\u0000.e30.sig",
		// Full-width characters
		"eyJhbGciOiJSUzI1NiJ9．e30．sig",
		// Unicode dots
		"eyJhbGciOiJSUzI1NiJ9\u2024e30\u2024sig",

		// === Malformed JSON in claims ===
		// Truncated JSON
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0.sig",
		// Invalid JSON
		"eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.sig",
		// Array instead of object
		"eyJhbGciOiJSUzI1NiJ9.W10.sig",

		// === Whitespace tricks ===
		" eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30.sig ",
		"\teyJhbGciOiJSUzI1NiJ9.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9 .e30.sig",
		"eyJhbGciOiJSUzI1NiJ9. e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30 .sig",
	}
}

// FuzzCookieSessionGetExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzCookieSessionGetExtended -fuzztime=60s .
func FuzzCookieSessionGetExtended(f *testing.F) {
	for _, seed := range fuzzSessionGetSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		store := NewCookieSessionStore(fuzzTestKey, time.Hour)
		session, err := store.Get(input)
		checkSessionGetInvariants(t, input, session, err)
	})
}

// fuzzParseMetadataSeedsExtended returns the full seed corpus for CI metadata parsing tests.
func fuzzParseMetadataSeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
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
		// SP-only metadata
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>`,
		// Invalid validUntil format
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="not-a-date"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Expired validUntil
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="2020-01-01T00:00:00Z"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// XXE attempt
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Null byte injection
		"<?xml version=\"1.0\"?><EntityDescriptor\x00 xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"/>",
		// Invalid UTF-8
		"<?xml version=\"1.0\"?><EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"\xff\xfe\"/>",
		// Very long entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + strings.Repeat("a", 10000) + `"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Extended XML attack patterns ===
		// XML bomb (billion laughs) - small version
		`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&lol3;"/>`,
		// External entity via parameter entity
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"/>`,
		// External entity via HTTP
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;"/>`,

		// === Deeply nested structures ===
		// Nested EntitiesDescriptor (3 levels)
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntitiesDescriptor><EntitiesDescriptor><EntityDescriptor entityID="https://deep.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://deep.example.com/sso"/></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor></EntitiesDescriptor></EntitiesDescriptor>`,
		// Deeply nested elements (10 levels of generic nesting)
		`<?xml version="1.0"?><a><b><c><d><e><f><g><h><i><j>deep</j></i></h></g></f></e></d></c></b></a>`,

		// === Mixed IdP/SP aggregates ===
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor><EntityDescriptor entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`,

		// === Namespace variations ===
		// No namespace
		`<?xml version="1.0"?><EntityDescriptor entityID="https://idp.example.com"><IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Wrong namespace
		`<?xml version="1.0"?><EntityDescriptor xmlns="http://wrong.namespace.com" entityID="https://idp.example.com"><IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Namespace prefix
		`<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`,

		// === CDATA and comments ===
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><!-- comment --><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/><![CDATA[some cdata content]]></IDPSSODescriptor></EntityDescriptor>`,

		// === Processing instructions ===
		`<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="evil.xsl"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Unicode edge cases ===
		// Unicode in entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/日本語"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Zero-width characters
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp​.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// BOM at start
		"\xef\xbb\xbf" + `<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === validUntil edge cases ===
		// Future validUntil
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="2099-12-31T23:59:59Z"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// validUntil with timezone offset
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil="2099-12-31T23:59:59+01:00"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Empty validUntil
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com" validUntil=""><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === SSO binding variations ===
		// HTTP-POST binding only
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Multiple SSO endpoints
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/></IDPSSODescriptor></EntityDescriptor>`,
		// No SSO endpoints
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor></EntityDescriptor>`,

		// === Empty/missing elements ===
		// Empty EntitiesDescriptor
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"></EntitiesDescriptor>`,
		// Empty EntityDescriptor
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://empty.example.com"></EntityDescriptor>`,
		// Missing entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Large inputs ===
		// Many IdPs in aggregate
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
			strings.Repeat(`<EntityDescriptor entityID="https://idp.example.com/"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`, 100) +
			`</EntitiesDescriptor>`,
		// Very long attribute value
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + strings.Repeat("a", 50000) + `"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Special characters in attributes ===
		// Encoded entities in entityID
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com?foo=bar&amp;baz=qux"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		// Quotes in attributes
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/&quot;test&quot;"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Binary/control characters ===
		// Control characters in content
		"<?xml version=\"1.0\"?><EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.com\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.com/sso\"/></IDPSSODescriptor>\x01\x02\x03</EntityDescriptor>",
		// High bytes
		"<?xml version=\"1.0\"?><EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.com\xfe\xff\"/>",
	}
}

// FuzzParseMetadataExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzParseMetadataExtended -fuzztime=60s .
func FuzzParseMetadataExtended(f *testing.F) {
	for _, seed := range fuzzParseMetadataSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		idps, validUntil, err := parseMetadata([]byte(input))
		checkParseMetadataInvariants(t, []byte(input), idps, validUntil, err)
	})
}

// fuzzXMLDsigVerifySeedsExtendedCI returns the full seed corpus for CI XML signature verification tests.
// This extends fuzzXMLDsigVerifySeedsExtended with additional attack patterns.
func fuzzXMLDsigVerifySeedsExtendedCI() []string {
	base := fuzzXMLDsigVerifySeedsExtended()

	extended := []string{
		// === Signature wrapping attacks ===
		// Multiple Signature elements (attacker injects second signature)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>eHl6</SignatureValue></Signature></Root>`,

		// Nested Signature element (signature inside signature)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/></Signature></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Signature with sibling unsigned content
		`<?xml version="1.0"?><Root xmlns="urn:test"><UnsignedEvil>malicious</UnsignedEvil><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Malformed DSig structures ===
		// Missing Reference element
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Empty Reference element
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Reference with external URI (SSRF attempt)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="http://evil.com/data"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YWJj</DigestValue></Reference></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Missing DigestValue
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></Reference></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Algorithm confusion attacks ===
		// Unknown algorithm URI
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://evil.com/custom-algorithm"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Empty algorithm attribute
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm=""/><SignatureMethod Algorithm=""/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// MD5 algorithm (weak/deprecated)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-md5"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// SHA1 algorithm (weak)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Namespace variations ===
		// ds: prefix
		`<?xml version="1.0"?><Root xmlns="urn:test"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue>YWJj</ds:SignatureValue></ds:Signature></Root>`,

		// Mixed namespace prefixes
		`<?xml version="1.0"?><Root xmlns="urn:test"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><ds:SignatureValue>YWJj</ds:SignatureValue></ds:Signature></Root>`,

		// Wrong namespace for Signature
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://wrong.namespace"><SignedInfo/><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === XXE in signature context ===
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="&xxe;"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === KeyInfo variations ===
		// KeyInfo with X509Data
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue><KeyInfo><X509Data><X509Certificate>YWJj</X509Certificate></X509Data></KeyInfo></Signature></Root>`,

		// KeyInfo with KeyValue (RSA)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>YWJj</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature></Root>`,

		// Empty KeyInfo
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue><KeyInfo/></Signature></Root>`,

		// === Large/boundary inputs ===
		// Very long SignatureValue
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>` + strings.Repeat("YWJj", 10000) + `</SignatureValue></Signature></Root>`,

		// Deeply nested elements inside Signature
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><a><b><c><d><e><f><g><h><i><j>deep</j></i></h></g></f></e></d></c></b></a></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Binary/control characters in signature ===
		"<?xml version=\"1.0\"?><Root xmlns=\"urn:test\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo/><SignatureValue>\x00\x01\x02</SignatureValue></Signature></Root>",

		// Invalid base64 in SignatureValue
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>!!!not-base64!!!</SignatureValue></Signature></Root>`,

		// === SAML-specific metadata with signature ===
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature><EntityDescriptor entityID="https://idp.example.com"/></EntitiesDescriptor>`,

		// Signature inside EntityDescriptor
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`,

		// === Transform attacks ===
		// XSLT transform (potential code execution)
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"/></xsl:stylesheet></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YWJj</DigestValue></Reference></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// Multiple transforms
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YWJj</DigestValue></Reference></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Unicode in signature elements ===
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#日本語"/></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,

		// === Comments inside signature ===
		`<?xml version="1.0"?><Root xmlns="urn:test"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><!-- comment --><SignedInfo><!-- another comment --></SignedInfo><SignatureValue>YWJj</SignatureValue></Signature></Root>`,
	}

	return append(base, extended...)
}

// FuzzXMLDsigVerifyExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzXMLDsigVerifyExtended -fuzztime=60s .
func FuzzXMLDsigVerifyExtended(f *testing.F) {
	for _, seed := range fuzzXMLDsigVerifySeedsExtendedCI() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		verifier := NewXMLDsigVerifier(fuzzTestCert)
		result, err := verifier.Verify([]byte(input))
		checkXMLDsigVerifyInvariants(t, []byte(input), result, err)
	})
}

// FuzzExtractAndValidateExpiryExtended uses full seed corpus for CI.
// Run with: go test -tags=fuzz_extended -fuzz=FuzzExtractAndValidateExpiryExtended -fuzztime=60s .
func FuzzExtractAndValidateExpiryExtended(f *testing.F) {
	for _, seed := range fuzzExtractAndValidateExpirySeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result, err := extractAndValidateExpiry([]byte(input))
		checkExtractAndValidateExpiryInvariants(t, input, result, err)
	})
}
