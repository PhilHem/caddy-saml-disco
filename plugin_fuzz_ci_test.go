//go:build fuzz_extended

package caddysamldisco

import (
	"strings"
	"testing"
	"time"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
)

// FuzzValidateRelayStateExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzValidateRelayStateExtended -fuzztime=60s .
func FuzzValidateRelayStateExtended(f *testing.F) {
	for _, seed := range fuzzRelayStateSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := caddyadapter.ValidateRelayState(input)
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

// fuzzExtractIdPInfoSeedsExtended returns the full seed corpus for CI IdP info extraction tests.
func fuzzExtractIdPInfoSeedsExtended() []string {
	base := fuzzExtractIdPInfoSeeds()
	extended := []string{
		// === Logo edge cases ===
		// Negative dimensions
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:Logo height="-1" width="-1">https://idp.example.com/logo.png</mdui:Logo></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Very large dimensions (potential overflow)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:Logo height="999999999" width="999999999">https://idp.example.com/logo.png</mdui:Logo></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Empty logo URL
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:Logo height="100" width="100"></mdui:Logo></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Multiple logos with different dimensions
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:Logo height="16" width="16">https://idp.example.com/small.png</mdui:Logo><mdui:Logo height="256" width="256">https://idp.example.com/large.png</mdui:Logo><mdui:Logo height="64" width="64">https://idp.example.com/medium.png</mdui:Logo></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Language code edge cases ===
		// Very long language code
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="` + strings.Repeat("x", 1000) + `">Long Language</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Special characters in language code
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en&lt;script&gt;">XSS Lang</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Numeric language code
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="12345">Numeric Lang</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === RegistrationInfo variations ===
		// Complete RegistrationInfo with policies
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" entityID="https://idp.example.com"><Extensions><mdrpi:RegistrationInfo registrationAuthority="https://fed.example.com" registrationInstant="2024-01-15T10:30:00Z"><mdrpi:RegistrationPolicy xml:lang="en">https://fed.example.com/policy</mdrpi:RegistrationPolicy><mdrpi:RegistrationPolicy xml:lang="de">https://fed.example.com/richtlinie</mdrpi:RegistrationPolicy></mdrpi:RegistrationInfo></Extensions><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Empty registration authority
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" entityID="https://idp.example.com"><Extensions><mdrpi:RegistrationInfo registrationAuthority="" registrationInstant="2024-01-15T10:30:00Z"/></Extensions><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Future registration instant
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi" entityID="https://idp.example.com"><Extensions><mdrpi:RegistrationInfo registrationAuthority="https://fed.example.com" registrationInstant="2099-12-31T23:59:59Z"/></Extensions><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === SSO binding variations ===
		// POST binding only
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/></IDPSSODescriptor></EntityDescriptor>`,

		// Both bindings (should prefer Redirect)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/></IDPSSODescriptor></EntityDescriptor>`,

		// No SSO endpoints
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor></EntityDescriptor>`,

		// Unknown binding type
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:CUSTOM" Location="https://idp.example.com/sso/custom"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Certificate edge cases ===
		// Multiple signing certificates
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...cert1...</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...cert2...</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Encryption-only key (should be ignored)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...encryptonly...</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Key with empty use (should be treated as signing)
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use=""><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...nouse...</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Organization fallback ===
		// Organization display name without UIInfo
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><Organization><OrganizationName xml:lang="en">Org Name</OrganizationName><OrganizationDisplayName xml:lang="en">Organization Display Name</OrganizationDisplayName><OrganizationURL xml:lang="en">https://org.example.com</OrganizationURL></Organization><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Empty Organization display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><Organization><OrganizationDisplayName xml:lang="en"></OrganizationDisplayName></Organization><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Aggregate metadata ===
		// EntitiesDescriptor with multiple IdPs
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp1.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/></IDPSSODescriptor></EntityDescriptor><EntityDescriptor entityID="https://idp2.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`,

		// Mixed IdP and SP in aggregate
		`<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor><EntityDescriptor entityID="https://sp.example.com"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`,

		// === Whitespace handling ===
		// Newlines and tabs in display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">
	Display
	Name
	With
	Whitespace
</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Leading/trailing spaces in URL
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:InformationURL xml:lang="en">  https://info.example.com  </mdui:InformationURL></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Comments and CDATA ===
		// Comment inside display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">Display<!-- hidden -->Name</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// CDATA in display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en"><![CDATA[CDATA Display Name]]></mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// === Unicode edge cases ===
		// Right-to-left text
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="ar">مزود الهوية</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Zero-width characters
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">Zero​Width</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,

		// Emoji in display name
		`<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><Extensions><mdui:UIInfo><mdui:DisplayName xml:lang="en">🔐 Secure IdP 🛡️</mdui:DisplayName></mdui:UIInfo></Extensions><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`,
	}

	return append(base, extended...)
}

// FuzzExtractIdPInfoExtended uses full seed corpus for CI.
// Run with: go test -tags=fuzz_extended -fuzz=FuzzExtractIdPInfoExtended -fuzztime=60s .
func FuzzExtractIdPInfoExtended(f *testing.F) {
	for _, seed := range fuzzExtractIdPInfoSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		idps, _, err := parseMetadata([]byte(input))
		checkExtractIdPInfoInvariants(t, []byte(input), idps, err)
		_ = err
	})
}

// fuzzParseAcceptLanguageSeedsExtended returns the full seed corpus for CI Accept-Language parsing tests.
func fuzzParseAcceptLanguageSeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
		"", "en", "de", "en-US",
		"de, en;q=0.9", "en;q=0.5, de;q=0.9",
		"*", "en;q=0", "   ",
		";;;", "q=0.5", "en;q=invalid",
		strings.Repeat("a", 10000),

		// === RFC 2616 quality edge cases ===
		"en;q=0.000", "en;q=1.000", "en;q=0.001",
		"en;q=0.999", "en;q=0.123456789",

		// === Whitespace variations ===
		"en , de", "en\t,\tde", "en\n,\nde",
		"en , de ; q=0.8", "en\t,\tde\t;\tq=0.8",
		"  en  ,  de  ", "\ten\t,\tde\t",

		// === Regional variants ===
		"zh-Hans-CN", "sr-Latn-RS", "pt-BR;q=0.9, pt-PT;q=0.8",
		"en-US, en-GB;q=0.9", "fr-CA, fr-FR;q=0.8",
		"es-ES, es-MX;q=0.9, es-AR;q=0.7",

		// === Unicode attacks ===
		"en\x00de", "en\ufeffde",
		"en\u200bde", // Zero-width space
		"en\u200cde", // Zero-width non-joiner

		// === Header injection attempts ===
		"en\r\nX-Injected: value",
		"en\nX-Injected: value",
		"en\rX-Injected: value",
		"en;q=0.9\r\nX-Injected: value",

		// === Multiple semicolons ===
		"en;q=0.9;q=0.5", "en;;q=0.9",
		"en;q=0.9;extra=value", "en;;;q=0.9",

		// === Negative/overflow quality ===
		"en;q=-1", "en;q=999999999",
		"en;q=-0.1", "en;q=2.0",
		"en;q=inf", "en;q=nan",

		// === Malformed quality values ===
		"en;q=", "en;q=.", "en;q=..",
		"en;q=abc", "en;q=0x10",
		"en;q=1e10", "en;q=1e-10",

		// === Empty/missing parts ===
		",", "en,", ",de",
		";", "en;", ";q=0.9",
		"en, ,de", "en,,de",

		// === Very long inputs ===
		strings.Repeat("en, ", 1000),
		strings.Repeat("en-US;q=0.9, ", 500),
	}
}

// FuzzParseAcceptLanguageExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzParseAcceptLanguageExtended -fuzztime=60s .
func FuzzParseAcceptLanguageExtended(f *testing.F) {
	for _, seed := range fuzzParseAcceptLanguageSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := caddyadapter.ParseAcceptLanguage(input)
		checkParseAcceptLanguageInvariants(t, input, result)
	})
}

// fuzzMatchesEntityIDPatternSeedsExtended returns the full seed corpus for CI entityID pattern matching tests.
func fuzzMatchesEntityIDPatternSeedsExtended() [][]string {
	base := fuzzMatchesEntityIDPatternSeeds()
	extended := [][]string{
		// === Very long inputs ===
		{strings.Repeat("a", 10000), "*"},
		{strings.Repeat("a", 10000), strings.Repeat("a", 5000) + "*"},
		{"https://idp.example.com", strings.Repeat("*", 1000)},
		{strings.Repeat("https://idp.example.com/", 100), "*example*"},

		// === Unicode normalization attacks ===
		{"https://idp.example.com", "https://idp.example.com"}, // Normal ASCII
		{"https://idp.example.com", "https://idp.example.com"}, // Same, but test normalization
		{"https://idp.example.com/日本語", "*日本語*"},
		{"https://idp.example.com/日本語", "https://*"},
		{"https://idp.example.com/日本語", "*.com/日本語"},

		// === Glob metacharacters (should be treated as literal) ===
		{"https://idp.example.com", "https://idp.example?com"},
		{"https://idp.example.com", "https://idp.example[com"},
		{"https://idp.example.com", "https://idp.example{com"},
		{"https://idp.example.com", "https://idp.example.com?"},
		{"https://idp.example.com", "https://idp.example.com[]"},
		{"https://idp.example.com", "https://idp.example.com{}"},

		// === Regex-like patterns (should be treated as literal) ===
		{"https://idp.example.com", ".*"},
		{"https://idp.example.com", ".+*"},
		{"https://idp.example.com", ".*+"},
		{"https://idp.example.com", ".*?*"},
		{"https://idp.example.com", "https://.*"},
		{"https://idp.example.com", ".*.com"},

		// === Null byte injection ===
		{"https://idp.example.com", "https://idp.example.com\x00"},
		{"https://idp.example.com\x00", "*"},
		{"https://idp.example.com", "\x00*"},
		{"https://idp.example.com", "*\x00"},

		// === Whitespace tricks ===
		{"https://idp.example.com", " https://idp.example.com"},
		{"https://idp.example.com", "https://idp.example.com "},
		{"https://idp.example.com", " https://idp.example.com "},
		{"https://idp.example.com", "* example *"},
		{"https://idp.example.com", "\t*"},
		{"https://idp.example.com", "*\n"},

		// === Multiple wildcards ===
		{"https://idp.example.com", "**"},
		{"https://idp.example.com", "***"},
		{"https://idp.example.com", "*example*test*"},
		{"https://idp.example.com", "https://*example*"},
		{"https://idp.example.com", "*example*.com"},

		// === Edge cases with wildcards ===
		{"*", "*"},
		{"*", "**"},
		{"**", "*"},
		{"**", "**"},
		{"https://idp.example.com", "*https://idp.example.com*"},
		{"https://idp.example.com", "https://idp.example.com*"},
		{"https://idp.example.com", "*https://idp.example.com"},

		// === Empty/whitespace entityID ===
		{"", ""},
		{"", "*"},
		{"   ", "*"},
		{"\t\n", "*"},
		{"", "test*"},
		{"", "*test"},

		// === Control characters ===
		{"https://idp.example.com", "https://idp.example.com\x01"},
		{"https://idp.example.com\x02", "*"},
		{"https://idp.example.com", "\x03*"},

		// === Special URL characters ===
		{"https://idp.example.com/path?query=value", "*path*"},
		{"https://idp.example.com/path?query=value", "*query*"},
		{"https://idp.example.com/path#fragment", "*fragment*"},
		{"https://idp.example.com:8080/path", "*:8080*"},
		{"https://user:pass@idp.example.com", "*@*"},

		// === Case sensitivity ===
		{"https://IDP.EXAMPLE.COM", "https://idp.example.com"},
		{"https://IDP.EXAMPLE.COM", "*example*"},
		{"https://IDP.EXAMPLE.COM", "*EXAMPLE*"},

		// === Pattern with literal asterisk ===
		{"https://idp.example.com", "https://idp.example.com*"},
		{"https://idp.example.com*", "*"},
		{"https://idp.example.com*", "https://idp.example.com*"},
		{"https://idp.example.com*", "*example*"},

		// === Very short patterns ===
		{"https://idp.example.com", "*"},
		{"https://idp.example.com", "**"},
		{"https://idp.example.com", "a*"},
		{"https://idp.example.com", "*a"},
		{"https://idp.example.com", "a*b"},

		// === Pattern matching entire entityID ===
		{"https://idp.example.com", "*https://idp.example.com*"},
		{"https://idp.example.com", "https://*example.com"},
		{"https://idp.example.com", "https://idp.*.com"},
		{"https://idp.example.com", "https://idp.example.*"},
	}

	return append(base, extended...)
}

// FuzzMatchesEntityIDPatternExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzMatchesEntityIDPatternExtended -fuzztime=60s .
func FuzzMatchesEntityIDPatternExtended(f *testing.F) {
	for _, seed := range fuzzMatchesEntityIDPatternSeedsExtended() {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, entityID, pattern string) {
		result := MatchesEntityIDPattern(entityID, pattern)
		checkMatchesEntityIDPatternInvariants(t, entityID, pattern, result)
	})
}

// fuzzParseDurationSeedsExtended returns the full seed corpus for CI duration parsing tests.
func fuzzParseDurationSeedsExtended() []string {
	base := fuzzParseDurationSeeds()
	extended := []string{
		// === Boundary values ===
		"106751d", "106752d", // At and just over max safe days
		"0d", "1d", "-1d",    // Edge cases around zero

		// === Various overflow patterns ===
		"9223372036854775807d", "-9223372036854775808d", // Max/min int64
		"999999999999999d", "1000000000000000d",          // Very large values
		"2147483647d", "-2147483648d",                   // Max/min int32

		// === Whitespace/encoding tricks ===
		" 30d", "30d ", "30\td", "30\nd",               // Whitespace
		"30d\r", "30d\n",                                // Control chars

		// === Mixed formats (should fail gracefully) ===
		"1d2h", "1h1d", "30d30m",                       // Mixed day/hour formats

		// === Decimal/float attempts ===
		"30.5d", "30.0d", "0.5d",                       // Decimal days

		// === Unicode and special chars ===
		"３０d", "30ｄ",                                  // Full-width chars
		"30d\x00", "\x0030d",                            // Null bytes

		// === Very long inputs ===
		strings.Repeat("9", 100) + "d",                 // Very long number
		strings.Repeat("d", 1000),                      // Many 'd' chars
	}
	return append(base, extended...)
}

// FuzzParseDurationExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzParseDurationExtended -fuzztime=60s .
func FuzzParseDurationExtended(f *testing.F) {
	for _, seed := range fuzzParseDurationSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		dur, err := caddyadapter.ParseDuration(input)
		checkParseDurationInvariants(t, input, dur, err)
	})
}
