package caddy

import (
	"fmt"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

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
		oid, friendlyName := domain.ResolveAttributeName(m.SAMLAttribute)

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
		// Re-default if sanitization removed all characters
		if sep == "" {
			sep = ";"
		}

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



