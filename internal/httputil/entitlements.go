package httputil

import (
	"fmt"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// EntitlementHeaderMapping maps an entitlement field to an HTTP header.
type EntitlementHeaderMapping struct {
	// Field is the entitlement field to map (e.g., "roles", "department").
	Field string `json:"field"`

	// HeaderName is the HTTP header name to set. Must start with "X-".
	HeaderName string `json:"header_name"`

	// Separator is the string used to join multiple values (for roles).
	// Defaults to ";" if empty.
	Separator string `json:"separator,omitempty"`
}

// MapEntitlementsToHeaders transforms entitlement results to HTTP headers.
func MapEntitlementsToHeaders(result *domain.EntitlementResult, mappings []EntitlementHeaderMapping) (map[string]string, error) {
	headers := make(map[string]string)

	for _, m := range mappings {
		// Validate header name
		if !domain.IsValidHeaderName(m.HeaderName) {
			return nil, fmt.Errorf("invalid header name %q: must start with X- and contain only A-Za-z0-9-", m.HeaderName)
		}

		var value string

		switch m.Field {
		case "roles":
			// Join roles with separator
			if len(result.Roles) > 0 {
				sep := m.Separator
				if sep == "" {
					sep = ";"
				}
				sep = domain.SanitizeHeaderValue(sep)
				// Re-default if sanitization removed all characters
				if sep == "" {
					sep = ";"
				}
				values := make([]string, 0, len(result.Roles))
				for _, role := range result.Roles {
					sanitized := domain.SanitizeHeaderValue(role)
					if sanitized != "" {
						values = append(values, sanitized)
					}
				}
				if len(values) > 0 {
					value = strings.Join(values, sep)
				}
			}

		default:
			// Metadata field
			if result.Metadata != nil {
				if v, ok := result.Metadata[m.Field]; ok {
					value = domain.SanitizeHeaderValue(v)
				}
			}
		}

		if value != "" {
			headers[m.HeaderName] = value
		}
	}

	return headers, nil
}
