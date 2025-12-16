package caddysamldisco

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxHeaderValueLength is the maximum length for HTTP header values.
// This prevents DoS attacks via extremely long attribute values.
const MaxHeaderValueLength = 8192

// oidRegistry maps OIDs to their friendly names and vice versa.
// This is a pure domain component with no external dependencies.
var oidRegistry = map[string]string{
	// eduPerson attributes
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6":  "eduPersonPrincipalName",
	"eduPersonPrincipalName":             "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":  "eduPersonEntitlement",
	"eduPersonEntitlement":                "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9":  "eduPersonScopedAffiliation",
	"eduPersonScopedAffiliation":         "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.10": "eduPersonTargetedID",
	"eduPersonTargetedID":                 "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
	// LDAP attributes
	"urn:oid:0.9.2342.19200300.100.1.3": "mail",
	"mail":                               "urn:oid:0.9.2342.19200300.100.1.3",
	"urn:oid:2.5.4.42":                  "givenName",
	"givenName":                          "urn:oid:2.5.4.42",
	"urn:oid:2.5.4.4":                   "sn",
	"sn":                                 "urn:oid:2.5.4.4",
	"urn:oid:2.16.840.1.113730.3.1.241": "displayName",
	"displayName":                        "urn:oid:2.16.840.1.113730.3.1.241",
	// SCHAC attributes
	"urn:oid:1.3.6.1.4.1.25178.1.2.9": "schacHomeOrganization",
	"schacHomeOrganization":           "urn:oid:1.3.6.1.4.1.25178.1.2.9",
}

// ResolveAttributeName resolves an attribute name to its OID and friendly name pair.
// If the input is a known OID, returns the OID and its friendly name.
// If the input is a known friendly name, returns the OID and friendly name.
// If the input is unknown, returns it unchanged for both OID and friendly name.
//
// This is a pure function with no side effects or I/O.
func ResolveAttributeName(name string) (oid, friendlyName string) {
	if name == "" {
		return "", ""
	}

	// Check if it's a known OID or friendly name
	if resolved, ok := oidRegistry[name]; ok {
		// If name is an OID, resolved is the friendly name
		if strings.HasPrefix(name, "urn:oid:") {
			return name, resolved
		}
		// If name is a friendly name, resolved is the OID
		return resolved, name
	}

	// Unknown name passes through unchanged
	return name, name
}

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

		// Resolve attribute name to both OID and friendly name
		oid, friendlyName := ResolveAttributeName(m.SAMLAttribute)

		// Try to look up attribute using both forms (IdP may send either)
		var values []string
		var exists bool

		// First try the configured form
		values, exists = attrs[m.SAMLAttribute]
		if !exists {
			// If configured as OID, try friendly name (IdP might send friendly name)
			if m.SAMLAttribute == oid && friendlyName != oid {
				values, exists = attrs[friendlyName]
			}
			// If configured as friendly name, try OID (IdP might send OID)
			if !exists && m.SAMLAttribute == friendlyName && oid != friendlyName {
				values, exists = attrs[oid]
			}
		}

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

// ApplyHeaderPrefix prepends prefix to header name.
// If prefix is empty, returns headerName unchanged.
func ApplyHeaderPrefix(prefix, headerName string) string {
	if prefix == "" {
		return headerName
	}
	return prefix + headerName
}

// MapAttributesToHeadersWithPrefix transforms SAML attributes to HTTP headers with optional prefix.
// This is a wrapper around MapAttributesToHeaders that applies a prefix to header names.
// If prefix is set, header names don't need to start with "X-" (the final combined name must be valid).
// If prefix is empty, existing validation applies (headers must start with "X-").
func MapAttributesToHeadersWithPrefix(attrs map[string][]string, mappings []AttributeMapping, prefix string) (map[string]string, error) {
	// If prefix is set, validate that it starts with X- and is valid
	if prefix != "" {
		if !IsValidHeaderName(prefix) {
			return nil, fmt.Errorf("invalid header prefix %q: must start with X- and contain only A-Za-z0-9-", prefix)
		}
	}

	// Create adjusted mappings for validation and processing
	adjustedMappings := make([]AttributeMapping, len(mappings))
	for i, m := range mappings {
		adjustedMappings[i] = m
		if prefix != "" {
			// When prefix is set, validate the final combined name
			finalName := ApplyHeaderPrefix(prefix, m.HeaderName)
			if !IsValidHeaderName(finalName) {
				return nil, fmt.Errorf("invalid header name %q with prefix %q: final name %q must start with X- and contain only A-Za-z0-9-", m.HeaderName, prefix, finalName)
			}
			// Temporarily set header name to final name so MapAttributesToHeaders validates correctly
			adjustedMappings[i].HeaderName = finalName
		} else {
			// Without prefix, validate the header name directly
			if !IsValidHeaderName(m.HeaderName) {
				return nil, fmt.Errorf("invalid header name %q: must start with X- and contain only A-Za-z0-9-", m.HeaderName)
			}
		}
	}

	// Map attributes to headers (using adjusted mappings)
	result, err := MapAttributesToHeaders(attrs, adjustedMappings)
	if err != nil {
		return nil, err
	}

	// If prefix was set, the result already has prefixed names from adjustedMappings
	// Otherwise, return as-is
	return result, nil
}
