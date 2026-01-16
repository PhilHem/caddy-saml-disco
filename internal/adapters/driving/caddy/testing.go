package caddy

import (
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// NewSAMLDiscoForTest creates a SAMLDisco instance with injected dependencies.
// This constructor is intended for testing purposes only.
//
// Deprecated: Use NewSAMLDisco with functional options instead.
// This function will be removed in v0.18.
//
//	s := NewSAMLDisco(
//	    WithConfig(config),
//	    WithSessionStore(sessionStore),
//	    WithSAMLService(samlService),
//	    WithMetadataStore(metadataStore),
//	)
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

	return NewSAMLDisco(
		WithConfig(config),
		WithSessionStore(sessionStore),
		WithSAMLService(samlService),
		WithMetadataStore(metadataStore),
		WithTemplateRenderer(renderer),
	)
}

// SetLogger sets the logger for testing purposes.
func (s *SAMLDisco) SetLogger(logger *zap.Logger) {
	s.logger = logger
}
