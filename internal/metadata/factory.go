package metadata

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/signature"
)

// BuildOptionsFromConfig constructs metadata store options from a config value.
// This is used by the Caddy provisioner to avoid duplicating option-building logic.
func BuildOptionsFromConfig(cfg *config.Config, logger *zap.Logger, rec ports.MetricsRecorder, version string) ([]MetadataOption, error) {
	var opts []MetadataOption
	if cfg.IdPFilter != "" {
		opts = append(opts, WithIdPFilter(cfg.IdPFilter))
	}
	if cfg.RegistrationAuthorityFilter != "" {
		opts = append(opts, WithRegistrationAuthorityFilter(cfg.RegistrationAuthorityFilter))
	}
	if cfg.EntityCategoryFilter != "" {
		opts = append(opts, WithEntityCategoryFilter(cfg.EntityCategoryFilter))
	}
	if cfg.AssuranceCertificationFilter != "" {
		opts = append(opts, WithAssuranceCertificationFilter(cfg.AssuranceCertificationFilter))
	}
	if cfg.VerifyMetadataSignature {
		certs, err := signature.LoadSigningCertificates(cfg.MetadataSigningCert)
		if err != nil {
			return nil, fmt.Errorf("load metadata signing certificate: %w", err)
		}
		verifier := signature.NewXMLDsigVerifierWithCertsAndLogger(certs, logger)
		opts = append(opts, WithSignatureVerifier(verifier))
		logger.Info("metadata signature verification enabled",
			zap.String("cert_file", cfg.MetadataSigningCert),
			zap.Int("cert_count", len(certs)))
	}
	opts = append(opts, WithLogger(logger))
	opts = append(opts, WithMetricsRecorder(rec))
	opts = append(opts, WithVersion(version))
	return opts, nil
}

// NewStoreFromConfig creates an unloaded metadata store based on a config value.
func NewStoreFromConfig(cfg *config.Config, refreshInterval time.Duration, opts []MetadataOption, logger *zap.Logger) (ports.MetadataStore, error) {
	if cfg.MetadataFile != "" {
		return NewFileMetadataStore(cfg.MetadataFile, opts...), nil
	}
	if cfg.MetadataURL != "" {
		if cfg.BackgroundRefresh {
			store := NewURLMetadataStoreWithRefresh(cfg.MetadataURL, refreshInterval, opts...)
			logger.Info("background metadata refresh enabled", zap.Duration("interval", refreshInterval))
			return store, nil
		}
		return NewURLMetadataStore(cfg.MetadataURL, refreshInterval, opts...), nil
	}
	return nil, nil
}

// BuildStore creates a metadata store from a list of MetadataSources.
// Returns a single store if only one source, or a CompositeMetadataStore for multiple sources.
// Returns nil if sources list is empty.
// Base options are inherited by all sources and merged with per-source options.
func BuildStore(sources []config.MetadataSource, baseOpts []MetadataOption) (ports.MetadataStore, error) {
	if len(sources) == 0 {
		return nil, nil
	}

	var stores []ports.MetadataStore

	for _, src := range sources {
		// Start with base options and add per-source options
		opts := make([]MetadataOption, len(baseOpts))
		copy(opts, baseOpts)

		// Apply per-source IdPFilter
		if src.IdPFilter != "" {
			opts = append(opts, WithIdPFilter(src.IdPFilter))
		}

		// Apply defaults to source
		src.SetDefaults()

		// Create store based on URL or File
		var store ports.MetadataStore
		if src.URL != "" {
			store = NewURLMetadataStore(src.URL, src.RefreshInterval, opts...)
		} else if src.File != "" {
			store = NewFileMetadataStore(src.File, opts...)
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
	return NewCompositeMetadataStore(stores), nil
}
