//go:build fuzz_extended

package caddysamldisco

import (
	"strings"
	"testing"
)

// =============================================================================
// Extended Fuzz Seeds (CI - Comprehensive)
// =============================================================================

func fuzzAttributeSeedsExtended() []struct {
	attrName  string
	attrValue string
	header    string
} {
	seeds := []struct {
		attrName  string
		attrValue string
		header    string
	}{
		// === Valid SAML attribute OIDs ===
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "user@example.com", "X-Remote-User"},           // eduPersonPrincipalName
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.7", "admin", "X-Entitlements"},                     // eduPersonEntitlement
		{"urn:oid:0.9.2342.19200300.100.1.3", "user@example.com", "X-Mail"},                 // mail
		{"urn:oid:2.5.4.42", "John", "X-Given-Name"},                                        // givenName
		{"urn:oid:2.5.4.4", "Doe", "X-Surname"},                                             // sn
		{"urn:oid:2.16.840.1.113730.3.1.241", "John Doe", "X-Display-Name"},                 // displayName
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.9", "staff@example.com", "X-Scoped-Affiliation"},   // eduPersonScopedAffiliation
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.10", "12345", "X-Targeted-ID"},                     // eduPersonTargetedID
		{"urn:oid:1.3.6.1.4.1.25178.1.2.9", "https://example.com", "X-Home-Organization"},   // schacHomeOrganization

		// === Friendly names ===
		{"eduPersonPrincipalName", "user@example.com", "X-EPPN"},
		{"mail", "test@test.org", "X-Email"},
		{"displayName", "Test User", "X-Name"},
		{"givenName", "Test", "X-First"},
		{"sn", "User", "X-Last"},

		// === Header injection via attribute values ===
		{"evil", "value\r\nSet-Cookie: evil=1", "X-Evil"},
		{"evil", "value\r\nLocation: http://evil.com", "X-Evil"},
		{"evil", "value\r\nX-Injected: yes", "X-Evil"},
		{"evil", "value\r\n\r\n<html>body</html>", "X-Evil"},
		{"evil", "value\rSet-Cookie: evil=1", "X-Evil"},
		{"evil", "value\nSet-Cookie: evil=1", "X-Evil"},
		{"evil", "\r\nSet-Cookie: evil=1", "X-Evil"},
		{"evil", "normal\r\n\r\nHTTP/1.1 200 OK", "X-Evil"},

		// === Double encoding bypasses ===
		{"encoded", "value%0d%0aInjected: yes", "X-Encoded"},
		{"encoded", "value%0D%0AInjected: yes", "X-Encoded"},
		{"encoded", "value%0d%0a%0d%0aBody", "X-Encoded"},
		{"encoded", "%0d%0aSet-Cookie: x=y", "X-Encoded"},

		// === Invalid header names (should be rejected) ===
		{"test", "value", "Authorization"},
		{"test", "value", "Cookie"},
		{"test", "value", "Host"},
		{"test", "value", "Content-Type"},
		{"test", "value", "Content-Length"},
		{"test", "value", "Transfer-Encoding"},
		{"test", "value", "Set-Cookie"},
		{"test", "value", "Proxy-Authorization"},
		{"test", "value", "WWW-Authenticate"},

		// === Header name injection ===
		{"test", "value", "X-Header\r\nEvil: yes"},
		{"test", "value", "X-Header\nEvil: yes"},
		{"test", "value", "X-Header: value\r\nEvil"},
		{"test", "value", "X-\r\nEvil"},
		{"test", "value", "X-Test Header"}, // Space
		{"test", "value", "X-Test\tHeader"}, // Tab
		{"test", "value", "X-Test;Header"},  // Semicolon

		// === Unicode normalization attacks ===
		{"unicode", "admin\u200Buser", "X-Unicode"},           // Zero-width space
		{"unicode", "admin\u00A0user", "X-Unicode"},           // Non-breaking space
		{"unicode", "\uFEFFvalue", "X-Unicode"},               // BOM
		{"unicode", "value\u2028newline", "X-Unicode"},        // Line separator
		{"unicode", "value\u2029para", "X-Unicode"},           // Paragraph separator
		{"unicode", "\u202Eevil", "X-Unicode"},                // RTL override
		{"unicode", "value\u0000null", "X-Unicode"},           // Null in unicode form

		// === Very long values (DoS prevention) ===
		{"long", strings.Repeat("a", 1000), "X-Long"},
		{"long", strings.Repeat("b", 5000), "X-Long"},
		{"long", strings.Repeat("c", 10000), "X-Long"},
		{"long", strings.Repeat("d", 50000), "X-Long"},
		{"long", strings.Repeat("e", 100000), "X-Long"},
		{"long", strings.Repeat("\r\n", 1000), "X-Long"},

		// === Empty and whitespace variations ===
		{"empty", "", "X-Empty"},
		{"space", " ", "X-Space"},
		{"spaces", "   ", "X-Spaces"},
		{"tab", "\t", "X-Tab"},
		{"tabs", "\t\t\t", "X-Tabs"},
		{"mixed", " \t \t ", "X-Mixed"},
		{"leading", "  value", "X-Leading"},
		{"trailing", "value  ", "X-Trailing"},
		{"newlines", "\n\n\n", "X-Newlines"},

		// === Null bytes ===
		{"null", "\x00", "X-Null"},
		{"null", "before\x00after", "X-Null"},
		{"null", "\x00\x00\x00", "X-Null"},
		{"null", "value\x00", "X-Null"},

		// === Control characters ===
		{"ctrl", "\x01\x02\x03", "X-Ctrl"},
		{"ctrl", "value\x07bell", "X-Ctrl"},
		{"ctrl", "value\x08backspace", "X-Ctrl"},
		{"ctrl", "value\x1Bescape", "X-Ctrl"},
		{"ctrl", "value\x7Fdel", "X-Ctrl"},

		// === Special URL-like values ===
		{"url", "http://evil.com", "X-URL"},
		{"url", "javascript:alert(1)", "X-URL"},
		{"url", "data:text/html,<script>", "X-URL"},
		{"url", "file:///etc/passwd", "X-URL"},

		// === JSON/XML in values ===
		{"json", `{"admin":true}`, "X-JSON"},
		{"json", `["admin","user"]`, "X-JSON"},
		{"xml", `<user admin="true"/>`, "X-XML"},
		{"xml", `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`, "X-XML"},

		// === SQL injection patterns (in attribute values) ===
		{"sql", "' OR '1'='1", "X-SQL"},
		{"sql", "admin'--", "X-SQL"},
		{"sql", "1; DROP TABLE users;--", "X-SQL"},

		// === Case sensitivity ===
		{"test", "value", "x-lowercase"},
		{"test", "value", "X-UPPERCASE"},
		{"test", "value", "X-MixedCase"},
		{"test", "value", "x-MiXeD"},

		// === Attribute name edge cases ===
		{"", "value", "X-EmptyAttr"},
		{" ", "value", "X-SpaceAttr"},
		{"attr name", "value", "X-AttrWithSpace"},
		{"attr\tname", "value", "X-AttrWithTab"},
		{"attr\nname", "value", "X-AttrWithNewline"},
		{"attr;name", "value", "X-AttrWithSemi"},
		{"attr=name", "value", "X-AttrWithEquals"},
	}

	return seeds
}

// =============================================================================
// Extended Fuzz Tests
// =============================================================================

func FuzzMapAttributesToHeadersExtended(f *testing.F) {
	// Add extended seed corpus
	for _, seed := range fuzzAttributeSeedsExtended() {
		f.Add(seed.attrName, seed.attrValue, seed.header)
	}

	f.Fuzz(func(t *testing.T, attrName, attrValue, headerName string) {
		attrs := map[string][]string{
			attrName: {attrValue},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrName, HeaderName: headerName},
		}

		result, err := MapAttributesToHeaders(attrs, mappings)

		// Check all invariants
		checkAttributeMappingInvariantsFuzz(t, attrs, mappings, result, err)
	})
}

func FuzzMapAttributesToHeadersExtended_MultiValue(f *testing.F) {
	// Extended multi-value seeds
	seeds := []struct {
		attrName  string
		val1      string
		val2      string
		val3      string
		header    string
		separator string
	}{
		// Normal cases
		{"roles", "admin", "user", "guest", "X-Roles", ";"},
		{"roles", "admin", "user", "guest", "X-Roles", ","},
		{"roles", "admin", "user", "guest", "X-Roles", "|"},

		// Injection in values
		{"evil", "val1\r\n", "val2", "val3", "X-Evil", ";"},
		{"evil", "val1", "\r\nval2", "val3", "X-Evil", ";"},
		{"evil", "val1", "val2", "val3\r\n", "X-Evil", ";"},

		// Injection in separator
		{"test", "a", "b", "c", "X-Test", "\r\n"},
		{"test", "a", "b", "c", "X-Test", "\n"},
		{"test", "a", "b", "c", "X-Test", "\r"},

		// Long values
		{"long", strings.Repeat("a", 3000), strings.Repeat("b", 3000), strings.Repeat("c", 3000), "X-Long", ";"},

		// Empty values
		{"empty", "", "", "", "X-Empty", ";"},
		{"partial", "val", "", "val", "X-Partial", ";"},
	}

	for _, seed := range seeds {
		f.Add(seed.attrName, seed.val1, seed.val2, seed.val3, seed.header, seed.separator)
	}

	f.Fuzz(func(t *testing.T, attrName, val1, val2, val3, headerName, separator string) {
		attrs := map[string][]string{
			attrName: {val1, val2, val3},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrName, HeaderName: headerName, Separator: separator},
		}

		result, err := MapAttributesToHeaders(attrs, mappings)

		checkAttributeMappingInvariantsFuzz(t, attrs, mappings, result, err)
	})
}
