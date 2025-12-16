package caddysamldisco

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxHeaderValueLength is the maximum length for HTTP header values.
// This prevents DoS attacks via extremely long attribute values.
const MaxHeaderValueLength = 8192

// AttributeMapping maps a SAML attribute to an HTTP header.
// This is a core domain model with no external dependencies.
type AttributeMapping struct {
	// SAMLAttribute is the SAML attribute name or OID to match.
	// Examples: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName", "mail"
	SAMLAttribute string `json:"saml_attribute"`

	// HeaderName is the HTTP header name to set. Must start with "X-".
	// Examples: "X-Remote-User", "X-Mail", "X-Entitlements"
	HeaderName string `json:"header_name"`

	// Separator is the string used to join multiple attribute values.
	// Defaults to ";" if empty (Shibboleth convention).
	// Common alternatives: "," (HTTP convention), "|"
	Separator string `json:"separator,omitempty"`
}

// MapAttributesToHeaders transforms SAML attributes to HTTP headers.
// This is a pure function with no side effects or I/O.
//
// Security guarantees:
//   - All header names must start with "X-" (prevents overwriting standard headers)
//   - All header names contain only valid characters (A-Za-z0-9-)
//   - Output values are sanitized (no CR/LF, bounded length, no null bytes)
//   - Missing attributes produce no header (not an empty string)
//
// Returns an error if any header name is invalid.
func MapAttributesToHeaders(attrs map[string][]string, mappings []AttributeMapping) (map[string]string, error) {
	result := make(map[string]string)

	for _, m := range mappings {
		// Validate header name
		if !IsValidHeaderName(m.HeaderName) {
			return nil, fmt.Errorf("invalid header name %q: must start with X- and contain only A-Za-z0-9-", m.HeaderName)
		}

		// Look up attribute
		values, exists := attrs[m.SAMLAttribute]
		if !exists || len(values) == 0 {
			continue
		}

		// Filter out empty values
		nonEmpty := make([]string, 0, len(values))
		for _, v := range values {
			if v != "" {
				nonEmpty = append(nonEmpty, v)
			}
		}
		if len(nonEmpty) == 0 {
			continue
		}

		// Determine separator
		sep := m.Separator
		if sep == "" {
			sep = ";"
		}
		// Sanitize separator too
		sep = sanitizeHeaderValue(sep)

		// Join and sanitize
		joined := strings.Join(nonEmpty, sep)
		sanitized := sanitizeHeaderValue(joined)

		// Only set header if we have a non-empty value after sanitization
		if sanitized != "" {
			result[m.HeaderName] = sanitized
		}
	}

	return result, nil
}

// IsValidHeaderName checks if a header name is valid for attribute mapping.
// Valid names must:
//   - Start with "X-" or "x-" (case-insensitive prefix)
//   - Be at least 3 characters long (X- plus at least one character)
//   - Contain only ASCII letters, digits, and hyphens after the prefix
func IsValidHeaderName(name string) bool {
	if len(name) < 3 {
		return false
	}

	// Check X- prefix (case-insensitive)
	prefix := strings.ToUpper(name[:2])
	if prefix != "X-" {
		return false
	}

	// Check remaining characters
	for i := 2; i < len(name); i++ {
		c := name[i]
		valid := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-'
		if !valid {
			return false
		}
	}

	return true
}

// sanitizeHeaderValue removes dangerous characters and enforces length limits.
// This prevents:
//   - HTTP header injection via CR/LF
//   - Null byte injection
//   - DoS via extremely long values
//   - Issues with control characters
func sanitizeHeaderValue(v string) string {
	if v == "" {
		return ""
	}

	var result strings.Builder
	result.Grow(min(len(v), MaxHeaderValueLength))

	for _, r := range v {
		// Skip control characters (including CR, LF, null)
		if r < 32 || r == 127 {
			continue
		}

		// Skip Unicode line/paragraph separators
		if r == '\u2028' || r == '\u2029' {
			continue
		}

		// Skip null in any form
		if r == 0 {
			continue
		}

		// Skip problematic Unicode characters
		if unicode.Is(unicode.Cf, r) { // Format characters (includes BOM, RTL override, etc.)
			continue
		}

		result.WriteRune(r)

		// Enforce length limit
		if result.Len() >= MaxHeaderValueLength {
			break
		}
	}

	return result.String()
}
