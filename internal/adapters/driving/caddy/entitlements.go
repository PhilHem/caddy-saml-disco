package caddy

import (
	"fmt"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// MapEntitlementsToHeaders transforms entitlement results to HTTP headers.
func MapEntitlementsToHeaders(result *domain.EntitlementResult, mappings []EntitlementHeaderMapping) (map[string]string, error) {
	headers := make(map[string]string)

	for _, m := range mappings {
		// Validate header name
		if !IsValidHeaderName(m.HeaderName) {
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
				sep = sanitizeHeaderValue(sep)
				// Re-default if sanitization removed all characters
				if sep == "" {
					sep = ";"
				}
				values := make([]string, 0, len(result.Roles))
				for _, role := range result.Roles {
					sanitized := sanitizeHeaderValue(role)
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
					value = sanitizeHeaderValue(v)
				}
			}
		}

		if value != "" {
			headers[m.HeaderName] = value
		}
	}

	return headers, nil
}



