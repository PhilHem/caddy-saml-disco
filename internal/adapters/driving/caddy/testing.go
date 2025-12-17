package caddy

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// NewSAMLDiscoForTest creates a SAMLDisco instance with injected dependencies.
// This constructor is intended for testing purposes only.
func NewSAMLDiscoForTest(
	config Config,
	sessionStore ports.SessionStore,
	samlService *SAMLService,
	metadataStore ports.MetadataStore,
) *SAMLDisco {
	// Initialize template renderer with embedded templates
	renderer, err := NewTemplateRenderer()
	if err != nil {
		// This should never fail with embedded templates
		panic("failed to load embedded templates: " + err.Error())
	}

	s := &SAMLDisco{
		Config: config,
	}
	s.SetSessionStore(sessionStore)
	s.SetSAMLService(samlService)
	s.SetMetadataStore(metadataStore)
	s.SetTemplateRenderer(renderer)

	return s
}



