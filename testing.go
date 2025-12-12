package caddysamldisco

// NewSAMLDiscoForTest creates a SAMLDisco instance with injected dependencies.
// This constructor is intended for testing purposes only.
func NewSAMLDiscoForTest(
	config Config,
	sessionStore SessionStore,
	samlService *SAMLService,
	metadataStore MetadataStore,
) *SAMLDisco {
	return &SAMLDisco{
		Config:        config,
		sessionStore:  sessionStore,
		samlService:   samlService,
		metadataStore: metadataStore,
	}
}
