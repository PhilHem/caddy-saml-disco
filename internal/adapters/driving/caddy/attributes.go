package caddy

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxHeaderValueLength is the maximum length for HTTP header values.
const MaxHeaderValueLength = 8192

// sanitizeHeaderValue removes dangerous characters and enforces length limits.
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}



