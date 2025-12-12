package caddysamldisco

// NewSAMLDiscoForTest creates a SAMLDisco instance with injected dependencies.
// This constructor is intended for testing purposes only.
func NewSAMLDiscoForTest(
	config Config,
	sessionStore SessionStore,
	samlService *SAMLService,
	metadataStore MetadataStore,
) *SAMLDisco {
	// Initialize template renderer with embedded templates
	renderer, err := NewTemplateRenderer()
	if err != nil {
		// This should never fail with embedded templates
		panic("failed to load embedded templates: " + err.Error())
	}

	return &SAMLDisco{
		Config:           config,
		sessionStore:     sessionStore,
		samlService:      samlService,
		metadataStore:    metadataStore,
		templateRenderer: renderer,
	}
}
