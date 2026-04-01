//go:build unit || integration

package caddy

import (
	"crypto/rsa"
	"crypto/x509"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/request"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// NewSAMLService creates a SAMLService backed by a simple in-memory request store.
// Intended for use in tests; does not start a background cleanup goroutine.
func NewSAMLService(entityID string, privateKey *rsa.PrivateKey, certificate *x509.Certificate) *samlsvc.SAMLService {
	return samlsvc.NewSAMLServiceWithStore(entityID, privateKey, certificate, request.NewInMemoryRequestStore())
}

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
	samlService *samlsvc.SAMLService,
	metadataStore ports.MetadataStore,
) *SAMLDisco {
	// Initialize template renderer with embedded templates
	renderer, err := discovery.NewTemplateRenderer()
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
