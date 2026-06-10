package caddy

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/logo"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
	"github.com/philiph/caddy-saml-disco/internal/session"
	"github.com/philiph/caddy-saml-disco/internal/signature"
)

func (s *SAMLDisco) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()
	s.logger.Debug("provisioning saml discovery service")
	if len(s.SPConfigs) == 0 {
		s.SPConfigs = []*SPConfig{{
			SPConfig: config.SPConfig{Config: s.Config},
		}}
	}
	s.initMetricsRecorder()
	if len(s.SPConfigs) > 1 || (len(s.SPConfigs) == 1 && s.SPConfigs[0].Hostname != "") {
		if err := validateSPConfigs(s.SPConfigs); err != nil {
			return fmt.Errorf("validate SP configs: %w", err)
		}
	}
	s.registry = NewSPConfigRegistry()
	for _, spCfg := range s.SPConfigs {
		spCfg.Config.SetDefaults()
		if err := s.provisionSPConfig(ctx, spCfg); err != nil {
			hostname := spCfg.Hostname
			if hostname == "" {
				hostname = "(default)"
			}
			return fmt.Errorf("provision SP config for %s: %w", hostname, err)
		}
		if err := s.registry.Add(spCfg); err != nil {
			return fmt.Errorf("add SP config to registry: %w", err)
		}
	}
	if len(s.SPConfigs) > 1 || (len(s.SPConfigs) == 1 && s.SPConfigs[0].Hostname != "") {
		s.logger.Info("saml discovery service provisioned (multi-SP mode)",
			zap.Int("sp_count", len(s.SPConfigs)),
			zap.String("version", getVersion()))
	} else {
		sp := s.SPConfigs[0]
		idpCount := 0
		if sp.metadataStore != nil {
			if idps, err := sp.metadataStore.ListIdPs(""); err == nil {
				idpCount = len(idps)
			}
		}
		logFields := []zap.Field{
			zap.String("entity_id", sp.EntityID),
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
	}
	return nil
}

func newSessionAndSAMLFromConfig(cfg *config.Config, logger *zap.Logger, signMetadata bool) (ports.SessionStore, *samlsvc.SAMLService, time.Duration, error) {
	if cfg.KeyFile == "" {
		return nil, nil, 0, nil
	}
	privateKey, err := session.LoadPrivateKey(cfg.KeyFile)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("load SP private key: %w", err)
	}
	duration, err := time.ParseDuration(cfg.SessionDuration)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("parse session duration: %w", err)
	}
	sessionStore := session.NewCookieSessionStore(privateKey, duration)
	var samlService *samlsvc.SAMLService
	if cfg.CertFile != "" {
		certificate, err := session.LoadCertificate(cfg.CertFile)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("load SP certificate: %w", err)
		}
		samlService = samlsvc.NewSAMLServiceWithStore(cfg.EntityID, privateKey, certificate, getSharedRequestStore())
		samlService.SetLogger(logger)
		if cfg.RequestTTL != "" {
			requestTTL, err := time.ParseDuration(cfg.RequestTTL)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("parse request_ttl: %w", err)
			}
			samlService.SetRequestTTL(requestTTL)
		}
		if signMetadata {
			signer := signature.NewXMLDsigSigner(privateKey, certificate)
			samlService.SetMetadataSigner(signer)
			logger.Info("SP metadata signing enabled")
		}
	}
	return sessionStore, samlService, duration, nil
}

func (s *SAMLDisco) provisionSPConfig(ctx caddy.Context, spCfg *SPConfig) error {
	spCfg.snapshotConfig()
	if s.metricsRecorder == nil {
		s.initMetricsRecorder()
	}
	refreshInterval, err := time.ParseDuration(spCfg.MetadataRefreshInterval)
	if err != nil {
		return fmt.Errorf("parse metadata refresh interval: %w", err)
	}
	metadataOpts, err := metadata.BuildOptionsFromConfig(&spCfg.Config, s.logger, s.getMetricsRecorder(), getVersion())
	if err != nil {
		return err
	}
	if spCfg.VerifyMetadataSignature && spCfg.Hostname != "" {
		s.logger.Info("metadata signature verification enabled (SP)", zap.String("hostname", spCfg.Hostname))
	}
	var store ports.MetadataStore
	var sourceType string
	if len(spCfg.MetadataSources) > 0 {
		store, err = metadata.BuildStore(spCfg.MetadataSources, metadataOpts)
		sourceType = "metadata sources"
	} else {
		store, err = metadata.NewStoreFromConfig(&spCfg.Config, refreshInterval, metadataOpts, s.logger)
		sourceType = "metadata from URL"
		if spCfg.MetadataFile != "" {
			sourceType = "metadata from file"
		}
	}
	if err != nil {
		return err
	}
	if store != nil {
		if loader, ok := store.(interface{ Load() error }); ok {
			if err := loader.Load(); err != nil {
				// A failed initial load (expired aggregate, unreachable upstream,
				// HTTP error) must never abort provisioning: the blast radius of
				// that would be every route in the Caddyfile, including non-SAML
				// reverse proxies. Start with an empty IdP list and recover via
				// background refresh. The parser still rejects expired metadata,
				// so degradation means an empty list, never serving stale entries.
				s.logger.Error("initial metadata load failed; starting with empty metadata, will recover via background refresh",
					zap.String("source", sourceType),
					zap.String("hostname", spCfg.Hostname),
					zap.Error(err))
				// Promote URL-backed stores to active background refresh so a
				// degraded store self-heals once the upstream serves fresh
				// metadata. File-backed stores do not implement the interface
				// and are left as-is (a static file has no upstream to retry).
				if starter, ok := store.(interface {
					StartBackgroundRefresh(time.Duration)
				}); ok {
					starter.StartBackgroundRefresh(refreshInterval)
				}
			}
		}
		spCfg.metadataStore = store
	}
	if spCfg.metadataStore != nil {
		spCfg.logoStore = logo.NewCachingLogoStore(spCfg.metadataStore, nil)
	}
	sessionStore, samlService, duration, err := newSessionAndSAMLFromConfig(&spCfg.Config, s.logger, spCfg.SignMetadata)
	if err != nil {
		return err
	}
	if sessionStore != nil {
		spCfg.sessionStore = sessionStore
		spCfg.sessionDuration = duration
	}
	if samlService != nil {
		spCfg.samlService = samlService
		if spCfg.SignMetadata && spCfg.Hostname != "" {
			s.logger.Info("SP metadata signing enabled", zap.String("hostname", spCfg.Hostname))
		}
	}
	if spCfg.EntitlementsFile != "" {
		entitlementStore := entitlements.NewFileEntitlementStore(spCfg.EntitlementsFile, s.logger)
		if err := entitlementStore.Refresh(ctx); err != nil {
			return fmt.Errorf("load entitlements file: %w", err)
		}
		spCfg.entitlementStore = entitlementStore
		s.logger.Info("entitlements file loaded",
			zap.String("hostname", spCfg.Hostname), zap.String("file", spCfg.EntitlementsFile))
		if spCfg.EntitlementsRefreshInterval != "" {
			interval, err := time.ParseDuration(spCfg.EntitlementsRefreshInterval)
			if err != nil {
				return fmt.Errorf("parse entitlements_refresh_interval: %w", err)
			}
			spCfg.entitlementRefreshWorker = entitlements.StartRefresh(entitlementStore, interval, s.logger)
			s.logger.Info("entitlements background refresh enabled",
				zap.String("hostname", spCfg.Hostname), zap.String("file", spCfg.EntitlementsFile),
				zap.Duration("interval", interval))
		}
	}
	if spCfg.TemplatesDir != "" {
		renderer, err := discovery.NewTemplateRendererWithDir(spCfg.TemplatesDir)
		if err != nil {
			return fmt.Errorf("load templates from %s: %w", spCfg.TemplatesDir, err)
		}
		spCfg.templateRenderer = renderer
	} else {
		renderer, err := discovery.NewTemplateRendererWithTemplate(spCfg.DiscoveryTemplate)
		if err != nil {
			return fmt.Errorf("load embedded templates: %w", err)
		}
		spCfg.templateRenderer = renderer
	}
	return nil
}

func (s *SAMLDisco) Validate() error { return s.Config.Validate() }
func (s *SAMLDisco) Cleanup() error {
	spCfgs := s.SPConfigs
	if s.registry != nil {
		spCfgs = s.registry.AllConfigs()
	}
	for _, sp := range spCfgs {
		if sp.samlService != nil {
			if err := sp.samlService.Close(); err != nil {
				return err
			}
		}
		if closer, ok := sp.metadataStore.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				return err
			}
		}
		if sp.entitlementRefreshWorker != nil {
			sp.entitlementRefreshWorker.Close()
		}
	}
	return nil
}
