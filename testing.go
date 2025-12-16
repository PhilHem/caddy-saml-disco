package caddysamldisco

import caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"

// NewSAMLDiscoForTest creates a SAMLDisco instance with injected dependencies.
// This constructor is intended for testing purposes only.
func NewSAMLDiscoForTest(
	config Config,
	sessionStore SessionStore,
	samlService *SAMLService,
	metadataStore MetadataStore,
) *SAMLDisco {
	// Use the adapter's constructor which has access to unexported fields
	return caddyadapter.NewSAMLDiscoForTest(
		config,
		sessionStore,
		samlService,
		metadataStore,
	)
}
