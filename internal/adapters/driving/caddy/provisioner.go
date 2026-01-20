package caddy

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Provision sets up the module.
func (s *SAMLDisco) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	s.logger.Debug("provisioning saml discovery service")

	// Check if we're in multi-SP mode
	if len(s.SPConfigs) > 0 {
		// Multi-SP mode: validate and provision each SP config
		if err := validateSPConfigs(s.SPConfigs); err != nil {
			return fmt.Errorf("validate SP configs: %w", err)
		}

		s.registry = NewSPConfigRegistry()
		for _, spCfg := range s.SPConfigs {
			// Set defaults for each SP config
			spCfg.Config.SetDefaults()

			// Provision this SP config
			if err := s.provisionSPConfig(ctx, spCfg); err != nil {
				return fmt.Errorf("provision SP config for %s: %w", spCfg.Hostname, err)
			}

			// Add to registry
			if err := s.registry.Add(spCfg); err != nil {
				return fmt.Errorf("add SP config to registry: %w", err)
			}
		}

		// Log successful provisioning
		s.logger.Info("saml discovery service provisioned (multi-SP mode)",
			zap.Int("sp_count", len(s.SPConfigs)),
			zap.String("version", getVersion()))
		return nil
	}

	// Single-SP mode: use existing logic (backward compatibility)
	s.Config.SetDefaults()

	// Snapshot config values to prevent mutation between validation and runtime
	// This ensures header names computed at validation time match those used at runtime.
	s.headerPrefixSnapshot = s.HeaderPrefix
	s.attributeHeadersSnapshot = make([]AttributeMapping, len(s.AttributeHeaders))
	copy(s.attributeHeadersSnapshot, s.AttributeHeaders)
	s.entitlementHeadersSnapshot = make([]EntitlementHeaderMapping, len(s.EntitlementHeaders))
	copy(s.entitlementHeadersSnapshot, s.EntitlementHeaders)

	// Initialize metrics recorder
	s.initMetricsRecorder()

	// Parse refresh interval for metadata cache TTL
	refreshInterval, err := time.ParseDuration(s.MetadataRefreshInterval)
	if err != nil {
		return fmt.Errorf("parse metadata refresh interval: %w", err)
	}

	// Build metadata store options
	metadataOpts, err := s.buildMetadataStoreOptions()
	if err != nil {
		return fmt.Errorf("build metadata store options: %w", err)
	}

	// Initialize metadata store: use new MetadataSources if configured,
	// otherwise fall back to old MetadataURL/MetadataFile for backward compatibility
	var store ports.MetadataStore
	if len(s.MetadataSources) > 0 {
		store, err = BuildMetadataStore(&s.Config, metadataOpts)
		if err != nil {
			return fmt.Errorf("build metadata store: %w", err)
		}
		if err := s.loadMetadataStore(store, "metadata"); err != nil {
			return err
		}
	} else {
		// Backward compatibility: use old single-source initialization
		store, err = s.initializeMetadataStore(refreshInterval, metadataOpts)
		if err != nil {
			return fmt.Errorf("initialize metadata store: %w", err)
		}
		sourceType := "metadata from URL"
		if s.MetadataFile != "" {
			sourceType = "metadata from file"
		}
		if err := s.loadMetadataStore(store, sourceType); err != nil {
			return err
		}
	}
	s.metadataStore = store

	// Initialize logo store if metadata store is configured
	if s.metadataStore != nil {
		s.logoStore = logo.NewCachingLogoStore(s.metadataStore, nil)
	}

	// Initialize session store and SAML service if key file is configured
	sessionStore, samlService, sessionDur, err := s.initializeSessionAndSAML()
	if err != nil {
		return fmt.Errorf("initialize session and SAML: %w", err)
	}
	s.sessionStore = sessionStore
	s.samlService = samlService
	s.sessionDuration = sessionDur

	// Parse remember IdP duration
	if s.Config.RememberIdPDuration != "" {
		rememberDur, err := ParseDuration(s.Config.RememberIdPDuration)
		if err != nil {
			return fmt.Errorf("parse remember IdP duration: %w", err)
		}
		s.rememberIdPDuration = rememberDur
	}

	// Initialize entitlement store if configured
	if s.EntitlementsFile != "" {
		entitlementStore := entitlements.NewFileEntitlementStore(s.EntitlementsFile, s.logger)
		if err := entitlementStore.Refresh(ctx); err != nil {
			return fmt.Errorf("load entitlements file: %w", err)
		}
		s.entitlementStore = entitlementStore
		s.logger.Info("entitlements file loaded",
			zap.String("file", s.EntitlementsFile))
	}

	// Initialize template renderer
	if s.TemplatesDir != "" {
		renderer, err := NewTemplateRendererWithDir(s.TemplatesDir)
		if err != nil {
			return fmt.Errorf("load templates from %s: %w", s.TemplatesDir, err)
		}
		s.templateRenderer = renderer
	} else {
		// Use the configured discovery template (default, fels, etc.)
		renderer, err := NewTemplateRendererWithTemplate(s.DiscoveryTemplate)
		if err != nil {
			return fmt.Errorf("load embedded templates: %w", err)
		}
		s.templateRenderer = renderer
	}

	// Log successful provisioning
	idpCount := 0
	if s.metadataStore != nil {
		if idps, err := s.metadataStore.ListIdPs(""); err == nil {
			idpCount = len(idps)
		}
	}
	logFields := []zap.Field{
		zap.String("entity_id", s.EntityID),
		zap.Int("idp_count", idpCount),
		zap.String("version", getVersion()),
	}
	if gitCommit := getGitCommit(); gitCommit != "" {
		logFields = append(logFields, zap.String("git_commit", gitCommit))
	}
	if buildTime := getBuildTime(); buildTime != "" {
		logFields = append(logFields, zap.String("build_time", buildTime))
	}
	s.logger.Info("saml discovery service provisioned", logFields...)

	return nil
}

// buildMetadataStoreOptions constructs metadata store options from configuration.
func (s *SAMLDisco) buildMetadataStoreOptions() ([]metadata.MetadataOption, error) {
	var metadataOpts []metadata.MetadataOption

	// Add filter options
	if s.IdPFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithIdPFilter(s.IdPFilter))
	}
	if s.RegistrationAuthorityFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithRegistrationAuthorityFilter(s.RegistrationAuthorityFilter))
	}
	if s.EntityCategoryFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithEntityCategoryFilter(s.EntityCategoryFilter))
	}
	if s.AssuranceCertificationFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithAssuranceCertificationFilter(s.AssuranceCertificationFilter))
	}

	// Configure signature verification if enabled
	if s.VerifyMetadataSignature {
		certs, err := signature.LoadSigningCertificates(s.MetadataSigningCert)
		if err != nil {
			return nil, fmt.Errorf("load metadata signing certificate: %w", err)
		}
		verifier := signature.NewXMLDsigVerifierWithCertsAndLogger(certs, s.logger)
		metadataOpts = append(metadataOpts, metadata.WithSignatureVerifier(verifier))
		s.logger.Info("metadata signature verification enabled",
			zap.String("cert_file", s.MetadataSigningCert),
			zap.Int("cert_count", len(certs)))
	}

	// Add infrastructure options
	metadataOpts = append(metadataOpts, metadata.WithLogger(s.logger))
	metadataOpts = append(metadataOpts, metadata.WithMetricsRecorder(s.getMetricsRecorder()))
	metadataOpts = append(metadataOpts, metadata.WithVersion(getVersion()))

	return metadataOpts, nil
}

// initializeMetadataStore creates a metadata store based on configuration.
// The store is not loaded - the caller is responsible for calling Load().
func (s *SAMLDisco) initializeMetadataStore(refreshInterval time.Duration, opts []metadata.MetadataOption) (ports.MetadataStore, error) {
	if s.MetadataFile != "" {
		store := metadata.NewFileMetadataStore(s.MetadataFile, opts...)
		return store, nil
	}

	if s.MetadataURL != "" {
		var store *metadata.URLMetadataStore
		if s.BackgroundRefresh {
			store = metadata.NewURLMetadataStoreWithRefresh(s.MetadataURL, refreshInterval, opts...)
			s.logger.Info("background metadata refresh enabled",
				zap.Duration("interval", refreshInterval))
		} else {
			store = metadata.NewURLMetadataStore(s.MetadataURL, refreshInterval, opts...)
		}
		return store, nil
	}

	return nil, nil
}

// loadMetadataStore loads metadata into a store if it supports the Load() method.
// Returns a formatted error with sourceType on failure.
func (s *SAMLDisco) loadMetadataStore(store ports.MetadataStore, sourceType string) error {
	if store == nil {
		return nil
	}
	if loader, ok := store.(interface{ Load() error }); ok {
		if err := loader.Load(); err != nil {
			return fmt.Errorf("load %s: %w", sourceType, err)
		}
	}
	return nil
}

// initializeSessionAndSAML creates session store and SAML service from configuration.
func (s *SAMLDisco) initializeSessionAndSAML() (ports.SessionStore, *SAMLService, time.Duration, error) {
	if s.KeyFile == "" {
		return nil, nil, 0, nil
	}

	privateKey, err := session.LoadPrivateKey(s.KeyFile)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("load SP private key: %w", err)
	}

	duration, err := time.ParseDuration(s.Config.SessionDuration)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("parse session duration: %w", err)
	}

	sessionStore := session.NewCookieSessionStore(privateKey, duration)

	var samlService *SAMLService
	if s.CertFile != "" {
		certificate, err := session.LoadCertificate(s.CertFile)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("load SP certificate: %w", err)
		}
		samlService = NewSAMLServiceWithCleanup(s.EntityID, privateKey, certificate, DefaultRequestCleanupInterval)

		// Configure metadata signing if enabled
		if s.SignMetadata {
			signer := signature.NewXMLDsigSigner(privateKey, certificate)
			samlService.SetMetadataSigner(signer)
			s.logger.Info("SP metadata signing enabled")
		}
	}

	return sessionStore, samlService, duration, nil
}

// provisionSPConfig provisions a single SP config with its metadata store, session store, and SAML service.
func (s *SAMLDisco) provisionSPConfig(ctx caddy.Context, spCfg *SPConfig) error {
	// Snapshot config values to prevent mutation between validation and runtime
	// This ensures header names computed at validation time match those used at runtime.
	spCfg.headerPrefixSnapshot = spCfg.HeaderPrefix
	spCfg.attributeHeadersSnapshot = make([]AttributeMapping, len(spCfg.AttributeHeaders))
	copy(spCfg.attributeHeadersSnapshot, spCfg.AttributeHeaders)
	spCfg.entitlementHeadersSnapshot = make([]EntitlementHeaderMapping, len(spCfg.EntitlementHeaders))
	copy(spCfg.entitlementHeadersSnapshot, spCfg.EntitlementHeaders)

	// Initialize metrics recorder if not already initialized
	if s.metricsRecorder == nil {
		s.initMetricsRecorder()
	}

	// Parse refresh interval for metadata cache TTL
	refreshInterval, err := time.ParseDuration(spCfg.MetadataRefreshInterval)
	if err != nil {
		return fmt.Errorf("parse metadata refresh interval: %w", err)
	}

	// Build metadata store options
	var metadataOpts []metadata.MetadataOption
	if spCfg.IdPFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithIdPFilter(spCfg.IdPFilter))
	}
	if spCfg.RegistrationAuthorityFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithRegistrationAuthorityFilter(spCfg.RegistrationAuthorityFilter))
	}
	if spCfg.EntityCategoryFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithEntityCategoryFilter(spCfg.EntityCategoryFilter))
	}
	if spCfg.AssuranceCertificationFilter != "" {
		metadataOpts = append(metadataOpts, metadata.WithAssuranceCertificationFilter(spCfg.AssuranceCertificationFilter))
	}

	// Configure signature verification if enabled
	if spCfg.VerifyMetadataSignature {
		certs, err := signature.LoadSigningCertificates(spCfg.MetadataSigningCert)
		if err != nil {
			return fmt.Errorf("load metadata signing certificate: %w", err)
		}
		verifier := signature.NewXMLDsigVerifierWithCertsAndLogger(certs, s.logger)
		metadataOpts = append(metadataOpts, metadata.WithSignatureVerifier(verifier))
		s.logger.Info("metadata signature verification enabled",
			zap.String("hostname", spCfg.Hostname),
			zap.String("cert_file", spCfg.MetadataSigningCert),
			zap.Int("cert_count", len(certs)))
	}

	// Pass logger to metadata store for background refresh logging
	metadataOpts = append(metadataOpts, metadata.WithLogger(s.logger))

	// Pass metrics recorder to metadata store for refresh metrics
	metadataOpts = append(metadataOpts, metadata.WithMetricsRecorder(s.getMetricsRecorder()))

	// Pass version for User-Agent header
	metadataOpts = append(metadataOpts, metadata.WithVersion(getVersion()))

	// Initialize metadata store based on config
	if spCfg.MetadataFile != "" {
		store := metadata.NewFileMetadataStore(spCfg.MetadataFile, metadataOpts...)
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from file: %w", err)
		}
		spCfg.metadataStore = store
	} else if spCfg.MetadataURL != "" {
		var store *metadata.URLMetadataStore
		if spCfg.BackgroundRefresh {
			store = metadata.NewURLMetadataStoreWithRefresh(spCfg.MetadataURL, refreshInterval, metadataOpts...)
			s.logger.Info("background metadata refresh enabled",
				zap.String("hostname", spCfg.Hostname),
				zap.Duration("interval", refreshInterval))
		} else {
			store = metadata.NewURLMetadataStore(spCfg.MetadataURL, refreshInterval, metadataOpts...)
		}
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from URL: %w", err)
		}
		spCfg.metadataStore = store
	}

	// Initialize logo store if metadata store is configured
	if spCfg.metadataStore != nil {
		spCfg.logoStore = logo.NewCachingLogoStore(spCfg.metadataStore, nil)
	}

	// Initialize session store and SAML service if key file is configured
	if spCfg.KeyFile != "" {
		privateKey, err := session.LoadPrivateKey(spCfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load SP private key: %w", err)
		}

		duration, err := time.ParseDuration(spCfg.Config.SessionDuration)
		if err != nil {
			return fmt.Errorf("parse session duration: %w", err)
		}

		spCfg.sessionStore = session.NewCookieSessionStore(privateKey, duration)
		spCfg.sessionDuration = duration

		// Initialize SAML service if certificate is also configured
		if spCfg.CertFile != "" {
			certificate, err := session.LoadCertificate(spCfg.CertFile)
			if err != nil {
				return fmt.Errorf("load SP certificate: %w", err)
			}
			spCfg.samlService = NewSAMLServiceWithCleanup(spCfg.EntityID, privateKey, certificate, DefaultRequestCleanupInterval)

			// Configure metadata signing if enabled
			if spCfg.SignMetadata {
				signer := signature.NewXMLDsigSigner(privateKey, certificate)
				spCfg.samlService.SetMetadataSigner(signer)
				s.logger.Info("SP metadata signing enabled",
					zap.String("hostname", spCfg.Hostname))
			}
		}
	}

	// Initialize entitlement store if configured
	if spCfg.EntitlementsFile != "" {
		entitlementStore := entitlements.NewFileEntitlementStore(spCfg.EntitlementsFile, s.logger)
		if err := entitlementStore.Refresh(ctx); err != nil {
			return fmt.Errorf("load entitlements file: %w", err)
		}
		spCfg.entitlementStore = entitlementStore
		s.logger.Info("entitlements file loaded",
			zap.String("hostname", spCfg.Hostname),
			zap.String("file", spCfg.EntitlementsFile))
	}

	// Initialize template renderer (shared across all SPs for now)
	// TODO: Consider per-SP template renderers if needed
	if spCfg.TemplatesDir != "" {
		renderer, err := NewTemplateRendererWithDir(spCfg.TemplatesDir)
		if err != nil {
			return fmt.Errorf("load templates from %s: %w", spCfg.TemplatesDir, err)
		}
		spCfg.templateRenderer = renderer
	} else {
		// Use the configured discovery template (default, fels, etc.)
		renderer, err := NewTemplateRendererWithTemplate(spCfg.DiscoveryTemplate)
		if err != nil {
			return fmt.Errorf("load embedded templates: %w", err)
		}
		spCfg.templateRenderer = renderer
	}

	return nil
}

// Validate ensures the module's configuration is valid.
func (s *SAMLDisco) Validate() error {
	return s.Config.Validate()
}

// Cleanup stops background goroutines when the module is unloaded.
// Implements caddy.CleanerUpper for graceful shutdown.
func (s *SAMLDisco) Cleanup() error {
	// Close the SAML service (stops request store cleanup goroutine)
	if s.samlService != nil {
		if err := s.samlService.Close(); err != nil {
			return err
		}
	}

	// Close the metadata store if it supports Close()
	if closer, ok := s.metadataStore.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			return err
		}
	}

	// Also cleanup SP config resources
	if s.registry != nil {
		for _, spCfg := range s.SPConfigs {
			// Close SP-specific SAML service
			if spCfg.samlService != nil {
				if err := spCfg.samlService.Close(); err != nil {
					return err
				}
			}
			// Close SP-specific metadata store
			if closer, ok := spCfg.metadataStore.(interface{ Close() error }); ok {
				if err := closer.Close(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
