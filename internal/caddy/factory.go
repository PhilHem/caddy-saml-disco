//go:build unit || integration

package caddy

// NewSAMLDisco creates a new SAMLDisco instance with the given options.
// This factory function provides a clean way to construct SAMLDisco instances
// with optional dependency injection, primarily for testing purposes.
//
// Example usage:
//
//	s := NewSAMLDisco(
//	    WithConfig(Config{EntityID: "https://sp.example.com"}),
//	    WithMetadataStore(myStore),
//	    WithLogger(logger),
//	)
func NewSAMLDisco(opts ...SAMLDiscoOption) *SAMLDisco {
	options := &samlDiscoOptions{}
	for _, opt := range opts {
		opt(options)
	}

	s := &SAMLDisco{}

	// Apply config if provided
	if options.config != nil {
		s.Config = *options.config
	}

	// Apply pinned IdPs (convenience option that overrides config)
	if len(options.pinnedIdPs) > 0 {
		s.PinnedIdPs = options.pinnedIdPs
	}

	// Apply optional dependencies via setters
	if options.metadataStore != nil {
		s.SetMetadataStore(options.metadataStore)
	}

	if options.sessionStore != nil {
		s.SetSessionStore(options.sessionStore)
	}

	if options.samlService != nil {
		s.SetSAMLService(options.samlService)
	}

	if options.logoStore != nil {
		s.SetLogoStore(options.logoStore)
	}

	if options.entitlementStore != nil {
		s.SetEntitlementStore(options.entitlementStore)
	}

	if options.metricsRecorder != nil {
		s.SetMetricsRecorder(options.metricsRecorder)
	}

	if options.templateRenderer != nil {
		s.SetTemplateRenderer(options.templateRenderer)
	}

	if options.logger != nil {
		s.SetLogger(options.logger)
	}

	return s
}
