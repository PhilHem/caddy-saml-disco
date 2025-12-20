package caddy

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// CaddyAttributeMapper implements the ports.AttributeMapper interface
// by delegating to the existing pure functions in this package.
type CaddyAttributeMapper struct{}

// NewCaddyAttributeMapper creates a new CaddyAttributeMapper instance.
func NewCaddyAttributeMapper() *CaddyAttributeMapper {
	return &CaddyAttributeMapper{}
}

// MapAttributesToHeaders implements ports.AttributeMapper.
func (m *CaddyAttributeMapper) MapAttributesToHeaders(attrs map[string][]string, mappings []ports.AttributeMapping) (map[string]string, error) {
	// Convert ports.AttributeMapping to caddy.AttributeMapping
	caddyMappings := make([]AttributeMapping, len(mappings))
	for i, pm := range mappings {
		caddyMappings[i] = AttributeMapping{
			SAMLAttribute: pm.SAMLAttribute,
			HeaderName:    pm.HeaderName,
			Separator:     pm.Separator,
		}
	}

	// Delegate to existing function
	return MapAttributesToHeaders(attrs, caddyMappings)
}

// MapAttributesToHeadersWithPrefix implements ports.AttributeMapper.
func (m *CaddyAttributeMapper) MapAttributesToHeadersWithPrefix(attrs map[string][]string, mappings []ports.AttributeMapping, prefix string) (map[string]string, error) {
	// Convert ports.AttributeMapping to caddy.AttributeMapping
	caddyMappings := make([]AttributeMapping, len(mappings))
	for i, pm := range mappings {
		caddyMappings[i] = AttributeMapping{
			SAMLAttribute: pm.SAMLAttribute,
			HeaderName:    pm.HeaderName,
			Separator:     pm.Separator,
		}
	}

	// Delegate to existing function
	return MapAttributesToHeadersWithPrefix(attrs, caddyMappings, prefix)
}



