package attributes

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// CaddyAttributeMapper implements the ports.AttributeMapper interface
// by delegating to domain functions.
type CaddyAttributeMapper struct{}

// NewCaddyAttributeMapper creates a new CaddyAttributeMapper instance.
func NewCaddyAttributeMapper() *CaddyAttributeMapper {
	return &CaddyAttributeMapper{}
}

// MapAttributesToHeaders implements ports.AttributeMapper.
func (m *CaddyAttributeMapper) MapAttributesToHeaders(attrs map[string][]string, mappings []ports.AttributeMapping) (map[string]string, error) {
	return domain.MapAttributesToHeaders(attrs, mappings)
}

// MapAttributesToHeadersWithPrefix implements ports.AttributeMapper.
func (m *CaddyAttributeMapper) MapAttributesToHeadersWithPrefix(attrs map[string][]string, mappings []ports.AttributeMapping, prefix string) (map[string]string, error) {
	return domain.MapAttributesToHeadersWithPrefix(attrs, mappings, prefix)
}
