package caddy

import (
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// BuildMetadataStore creates a metadata store from a list of MetadataSources.
// Returns a single store if only one source, or a CompositeMetadataStore for multiple sources.
// Returns nil if sources list is empty.
// Base options are inherited by all sources and merged with per-source options.
func BuildMetadataStore(cfg *Config, baseOpts []metadata.MetadataOption) (ports.MetadataStore, error) {
	if len(cfg.MetadataSources) == 0 {
		return nil, nil
	}

	var stores []ports.MetadataStore

	for _, src := range cfg.MetadataSources {
		// Start with base options and add per-source options
		opts := make([]metadata.MetadataOption, len(baseOpts))
		copy(opts, baseOpts)

		// Apply per-source IdPFilter
		if src.IdPFilter != "" {
			opts = append(opts, metadata.WithIdPFilter(src.IdPFilter))
		}

		// Apply defaults to source
		src.SetDefaults()

		// Create store based on URL or File
		var store ports.MetadataStore
		if src.URL != "" {
			store = metadata.NewURLMetadataStore(src.URL, src.RefreshInterval, opts...)
		} else if src.File != "" {
			store = metadata.NewFileMetadataStore(src.File, opts...)
		}

		if store != nil {
			stores = append(stores, store)
		}
	}

	// Return single store directly if only one source
	if len(stores) == 1 {
		return stores[0], nil
	}

	// Wrap multiple stores in CompositeMetadataStore
	return metadata.NewCompositeMetadataStore(stores), nil
}
