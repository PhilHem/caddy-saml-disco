package metadata

import (
	"encoding/xml"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// rawEntityDescriptorForScope is used to parse shibmd:Scope from raw XML.
// Scope is at IDPSSODescriptor/Extensions level.
type rawEntityDescriptorForScope struct {
	EntityID          string `xml:"entityID,attr"`
	IDPSSODescriptors []struct {
		Extensions struct {
			Scopes []struct {
				Value  string `xml:",chardata"`
				Regexp bool   `xml:"regexp,attr"`
			} `xml:"urn:mace:shibboleth:metadata:1.0 Scope"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
}

// rawEntitiesDescriptorForScope is used to parse shibmd:Scope from aggregate metadata.
type rawEntitiesDescriptorForScope struct {
	EntityDescriptors   []rawEntityDescriptorForScope   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptors []rawEntitiesDescriptorForScope `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

// parseAllScopes extracts shibmd:Scope for all entities from raw XML.
func parseAllScopes(data []byte) map[string][]domain.ScopeInfo {
	result := make(map[string][]domain.ScopeInfo)

	// Try parsing as EntitiesDescriptor (aggregate)
	var entities rawEntitiesDescriptorForScope
	if err := xml.Unmarshal(data, &entities); err == nil {
		extractScopesFromEntities(&entities, result)
		if len(result) > 0 {
			return result
		}
	}

	// Try parsing as single EntityDescriptor
	var entity rawEntityDescriptorForScope
	if err := xml.Unmarshal(data, &entity); err == nil {
		if len(entity.IDPSSODescriptors) > 0 && len(entity.IDPSSODescriptors[0].Extensions.Scopes) > 0 {
			scopes := make([]domain.ScopeInfo, len(entity.IDPSSODescriptors[0].Extensions.Scopes))
			for i, s := range entity.IDPSSODescriptors[0].Extensions.Scopes {
				scopes[i] = domain.ScopeInfo{
					Value:  s.Value,
					Regexp: s.Regexp,
				}
			}
			result[entity.EntityID] = scopes
		}
	}

	return result
}

// extractScopesFromEntities recursively extracts scopes from EntitiesDescriptor.
func extractScopesFromEntities(entities *rawEntitiesDescriptorForScope, result map[string][]domain.ScopeInfo) {
	for _, ed := range entities.EntityDescriptors {
		if len(ed.IDPSSODescriptors) > 0 && len(ed.IDPSSODescriptors[0].Extensions.Scopes) > 0 {
			scopes := make([]domain.ScopeInfo, len(ed.IDPSSODescriptors[0].Extensions.Scopes))
			for i, s := range ed.IDPSSODescriptors[0].Extensions.Scopes {
				scopes[i] = domain.ScopeInfo{
					Value:  s.Value,
					Regexp: s.Regexp,
				}
			}
			result[ed.EntityID] = scopes
		}
	}
	for i := range entities.EntitiesDescriptors {
		extractScopesFromEntities(&entities.EntitiesDescriptors[i], result)
	}
}
