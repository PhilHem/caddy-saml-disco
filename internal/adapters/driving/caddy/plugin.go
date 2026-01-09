package caddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/signature"
)

// HealthResponse is the JSON response for /saml/api/health
type HealthResponse struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	domain.MetadataHealth
}

// sessionContextKey is the context key for storing session data.
type sessionContextKey struct{}

// GetSession retrieves the authenticated session from the request context.
// Returns nil if no session is present (unauthenticated request).
func GetSession(r *http.Request) *domain.Session {
	session, _ := r.Context().Value(sessionContextKey{}).(*domain.Session)
	return session
}

// SAMLDisco is a Caddy HTTP handler module that provides SAML SP authentication
// with IdP discovery service support.
type SAMLDisco struct {
	// Configuration embedded directly (for backward compatibility with single-SP mode)
	Config

	// Multi-SP support
	// If SPConfigs is non-empty, the instance operates in multi-SP mode.
	// Otherwise, it uses the embedded Config (single-SP mode).
	SPConfigs []*SPConfig `json:"sp_configs,omitempty"`

	// Runtime state (not serialized)
	registry            *SPConfigRegistry
	metadataStore       ports.MetadataStore
	sessionStore        ports.SessionStore
	logoStore           ports.LogoStore
	entitlementStore    ports.EntitlementStore
	samlService         *SAMLService
	sessionDuration     time.Duration
	rememberIdPDuration time.Duration
	templateRenderer    *TemplateRenderer
	logger              *zap.Logger
	metricsRecorder     ports.MetricsRecorder

	// Config snapshots (immutable copies taken during Provision to prevent mutation)
	// These are used in applyAttributeHeaders() to ensure header names match validation-time expectations.
	headerPrefixSnapshot       string
	attributeHeadersSnapshot   []AttributeMapping
	entitlementHeadersSnapshot []EntitlementHeaderMapping
}

// SetLogoStore sets the logo store. For testing purposes.
func (s *SAMLDisco) SetLogoStore(store ports.LogoStore) {
	s.logoStore = store
}

// SPConfigRegistry manages multiple SP configurations keyed by hostname.
type SPConfigRegistry struct {
	configs map[string]*SPConfig // hostname -> config
	mu      sync.RWMutex
}

// NewSPConfigRegistry creates a new SP config registry.
func NewSPConfigRegistry() *SPConfigRegistry {
	return &SPConfigRegistry{
		configs: make(map[string]*SPConfig),
	}
}

// Add adds an SP config to the registry.
func (r *SPConfigRegistry) Add(cfg *SPConfig) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if cfg.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configs[cfg.Hostname] = cfg
	return nil
}

// GetByHostname retrieves an SP config by hostname.
// Returns nil if no config is found for the hostname.
func (r *SPConfigRegistry) GetByHostname(hostname string) *SPConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.configs[hostname]
}

// CaddyModule returns the Caddy module information.
func (SAMLDisco) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.saml_disco",
		New: func() caddy.Module { return new(SAMLDisco) },
	}
}

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
	var metadataOpts []metadata.MetadataOption
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
			return fmt.Errorf("load metadata signing certificate: %w", err)
		}
		verifier := signature.NewXMLDsigVerifierWithCertsAndLogger(certs, s.logger)
		metadataOpts = append(metadataOpts, metadata.WithSignatureVerifier(verifier))
		s.logger.Info("metadata signature verification enabled",
			zap.String("cert_file", s.MetadataSigningCert),
			zap.Int("cert_count", len(certs)))
	}

	// Pass logger to metadata store for background refresh logging
	metadataOpts = append(metadataOpts, metadata.WithLogger(s.logger))

	// Pass metrics recorder to metadata store for refresh metrics
	metadataOpts = append(metadataOpts, metadata.WithMetricsRecorder(s.getMetricsRecorder()))

	// Pass version for User-Agent header
	metadataOpts = append(metadataOpts, metadata.WithVersion(getVersion()))

	// Initialize metadata store based on config
	if s.MetadataFile != "" {
		store := metadata.NewFileMetadataStore(s.MetadataFile, metadataOpts...)
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from file: %w", err)
		}
		s.metadataStore = store
	} else if s.MetadataURL != "" {
		var store *metadata.URLMetadataStore
		if s.BackgroundRefresh {
			store = metadata.NewURLMetadataStoreWithRefresh(s.MetadataURL, refreshInterval, metadataOpts...)
			s.logger.Info("background metadata refresh enabled",
				zap.Duration("interval", refreshInterval))
		} else {
			store = metadata.NewURLMetadataStore(s.MetadataURL, refreshInterval, metadataOpts...)
		}
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from URL: %w", err)
		}
		s.metadataStore = store
	}

	// Initialize logo store if metadata store is configured
	if s.metadataStore != nil {
		s.logoStore = logo.NewCachingLogoStore(s.metadataStore, nil)
	}

	// Initialize session store and SAML service if key file is configured
	if s.KeyFile != "" {
		privateKey, err := session.LoadPrivateKey(s.KeyFile)
		if err != nil {
			return fmt.Errorf("load SP private key: %w", err)
		}

		duration, err := time.ParseDuration(s.SessionDuration)
		if err != nil {
			return fmt.Errorf("parse session duration: %w", err)
		}

		s.sessionStore = session.NewCookieSessionStore(privateKey, duration)
		s.sessionDuration = duration

		// Initialize SAML service if certificate is also configured
		if s.CertFile != "" {
			certificate, err := session.LoadCertificate(s.CertFile)
			if err != nil {
				return fmt.Errorf("load SP certificate: %w", err)
			}
			s.samlService = NewSAMLServiceWithCleanup(s.EntityID, privateKey, certificate, DefaultRequestCleanupInterval)

			// Configure metadata signing if enabled
			if s.SignMetadata {
				signer := signature.NewXMLDsigSigner(privateKey, certificate)
				s.samlService.SetMetadataSigner(signer)
				s.logger.Info("SP metadata signing enabled")
			}
		}
	}

	// Parse remember IdP duration
	if s.RememberIdPDuration != "" {
		rememberDur, err := ParseDuration(s.RememberIdPDuration)
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

		duration, err := time.ParseDuration(spCfg.SessionDuration)
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

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Determine which SP config to use
	var spConfig *SPConfig
	if s.registry != nil && len(s.SPConfigs) > 0 {
		// Multi-SP mode: route by hostname
		spConfig = s.registry.GetByHostname(r.Host)
		if spConfig == nil {
			return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("no SP config for hostname %q", r.Host))
		}
	} else {
		// Single-SP mode: use embedded Config (backward compatibility)
		spConfig = &SPConfig{
			Hostname: r.Host, // Use request hostname for single-SP mode
			Config:   s.Config,
			// Copy instance-level stores/services
			metadataStore:    s.metadataStore,
			sessionStore:     s.sessionStore,
			entitlementStore: s.entitlementStore,
			logoStore:        s.logoStore,
			samlService:      s.samlService,
			sessionDuration:  s.sessionDuration,
			templateRenderer: s.templateRenderer,
		}
	}

	// Delegate to SP-specific handler
	return s.serveSPRequest(w, r, next, spConfig)
}

// serveSPRequest handles a request for a specific SP config.
func (s *SAMLDisco) serveSPRequest(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, spConfig *SPConfig) error {
	// Handle CORS for API endpoints
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		s.applyCORSHeaders(w, r)

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
	}

	// Handle logo endpoint (path prefix pattern)
	if strings.HasPrefix(r.URL.Path, "/saml/api/logo/") && r.Method == http.MethodGet {
		return s.handleLogoEndpointForSP(w, r, spConfig)
	}

	// Route SAML endpoints
	switch r.URL.Path {
	case "/saml/metadata":
		if r.Method == http.MethodGet {
			return s.handleMetadataForSP(w, r, spConfig)
		}
	case "/saml/acs":
		if r.Method == http.MethodPost {
			return s.handleACSForSP(w, r, spConfig)
		}
	case "/saml/logout":
		if r.Method == http.MethodGet {
			return s.handleLogoutForSP(w, r, spConfig)
		}
	case "/saml/slo":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			return s.handleSLOForSP(w, r, spConfig)
		}
	case "/saml/api/idps":
		if r.Method == http.MethodGet {
			return s.handleListIdPsForSP(w, r, spConfig)
		}
	case "/saml/api/select":
		if r.Method == http.MethodPost {
			return s.handleSelectIdPForSP(w, r, spConfig)
		}
	case "/saml/api/session":
		if r.Method == http.MethodGet {
			return s.handleSessionInfoForSP(w, r, spConfig)
		}
	case "/saml/api/health":
		if r.Method == http.MethodGet {
			return s.handleHealthForSP(w, r, spConfig)
		}
	case "/saml/disco":
		if r.Method == http.MethodGet {
			return s.handleDiscoveryUIForSP(w, r, spConfig)
		}
	}

	// Check session for protected routes (skip SAML endpoints)
	if spConfig.sessionStore != nil && !strings.HasPrefix(r.URL.Path, "/saml/") {
		cookie, err := r.Cookie(spConfig.SessionCookieName)
		if err != nil || cookie.Value == "" {
			s.redirectToIdPForSP(w, r, spConfig)
			return nil
		}

		// Validate session token
		session, err := spConfig.sessionStore.Get(cookie.Value)
		if err != nil {
			s.getMetricsRecorder().RecordSessionValidation(false)
			s.redirectToIdPForSP(w, r, spConfig)
			return nil
		}
		s.getMetricsRecorder().RecordSessionValidation(true)

		// Store session in context for downstream handlers
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		r = r.WithContext(ctx)

		// Apply attribute-to-header mapping if configured
		// Check both AttributeHeaders and EntitlementHeaders
		if len(spConfig.AttributeHeaders) > 0 || len(spConfig.EntitlementHeaders) > 0 {
			s.applyAttributeHeadersForSP(r, session, spConfig)
		}
	}

	// Pass through to next handler
	return next.ServeHTTP(w, r)
}

// redirectToIdP redirects the user to authenticate.
// If LoginRedirect is configured, redirects to custom login UI.
// Otherwise, redirects directly to the IdP (single IdP scenario).
// The original URL is passed as return_url/RelayState so ACS can redirect back after login.
func (s *SAMLDisco) redirectToIdP(w http.ResponseWriter, r *http.Request) {
	// If LoginRedirect is configured, redirect to custom UI
	if s.LoginRedirect != "" {
		redirectURL := s.LoginRedirect
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Check if metadata store is configured
	if s.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return
	}

	// Get IdPs from metadata store
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderAppError(w, r, domain.ConfigError("No identity provider is configured"))
		return
	}

	// Multiple IdPs - redirect to discovery page for user selection
	if len(idps) > 1 {
		redirectURL := "/saml/disco?return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Single IdP - check SAML service and redirect directly
	if s.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return
	}
	idp := &idps[0]

	// Compute ACS URL and use original URL as RelayState
	acsURL := s.resolveAcsURL(r)
	relayState := r.URL.RequestURI()

	// Determine if forceAuthn is needed
	opts := &domain.AuthnOptions{
		ForceAuthn: s.ForceAuthn || MatchesForceAuthnPath(r.URL.Path, s.ForceAuthnPaths),
	}

	// Generate AuthnRequest and redirect URL
	redirectURL, err := s.samlService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleMetadata serves the SP metadata XML.
func (s *SAMLDisco) handleMetadata(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	acsURL := s.resolveAcsURL(r)
	metadata, err := s.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to generate metadata"))
		return err
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
	return nil
}

// handleACS processes the SAML Response from the IdP.
func (s *SAMLDisco) handleACS(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	// Parse form to get SAMLResponse
	if err := r.ParseForm(); err != nil {
		s.renderAppError(w, r, domain.BadRequestError("Invalid form data"))
		return err
	}

	// Extract Issuer from SAML response to find the correct IdP
	issuer, err := ExtractResponseIssuer(r.PostForm.Get("SAMLResponse"))
	if err != nil {
		s.getLogger().Warn("failed to extract issuer from SAML response",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, domain.BadRequestError("Invalid SAML response"))
		return err
	}

	// Look up IdP by Issuer entity ID
	idp, err := s.metadataStore.GetIdP(issuer)
	if err != nil {
		s.getLogger().Warn("unknown IdP issuer in SAML response",
			zap.String("issuer", issuer),
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, domain.AuthError("Unknown identity provider", err))
		return err
	}

	acsURL := s.resolveAcsURL(r)
	start := time.Now()
	result, err := s.samlService.HandleACS(r, acsURL, idp)
	duration := time.Since(start)
	if err != nil {
		details := ParseSAMLError(err)
		category := string(details.Category)

		// Build structured log fields
		// @tra: Adapter.SAMLAuthErrors
		fields := []zap.Field{
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("error_category", category),
			zap.String("idp_entity_id", idp.EntityID),
		}
		if details.PrivateError != "" {
			fields = append(fields, zap.String("private_error", details.PrivateError))
		}
		if details.IdPStatus != nil {
			fields = append(fields, zap.String("idp_status_code", details.IdPStatus.StatusCode))
			if details.IdPStatus.StatusMessage != "" {
				fields = append(fields, zap.String("idp_status_message", details.IdPStatus.StatusMessage))
			}
		}
		if details.TimeContext != nil {
			fields = append(fields, zap.Time("server_time", details.TimeContext.ServerTime))
		}
		s.getLogger().Warn("saml authentication failed", fields...)

		s.getMetricsRecorder().RecordAuthAttempt(idp.EntityID, false)
		s.getMetricsRecorder().RecordAuthFailure(category, idp.EntityID)
		s.getMetricsRecorder().RecordAuthDuration(idp.EntityID, "failure", duration)
		s.renderAppError(w, r, domain.AuthError("SAML authentication failed", err))
		return nil
	}

	s.getLogger().Info("saml authentication successful",
		zap.String("subject", result.Subject),
		zap.String("idp_entity_id", result.IdPEntityID),
	)
	s.getMetricsRecorder().RecordAuthAttempt(result.IdPEntityID, true)
	s.getMetricsRecorder().RecordAuthSuccess(result.IdPEntityID)
	s.getMetricsRecorder().RecordAuthDuration(result.IdPEntityID, "success", duration)

	// Create session
	session := &domain.Session{
		Subject:      result.Subject,
		Attributes:   result.Attributes,
		IdPEntityID:  result.IdPEntityID,
		NameIDFormat: result.NameIDFormat,
		SessionIndex: result.SessionIndex,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(s.sessionDuration),
	}

	token, err := s.sessionStore.Create(session)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}
	s.getMetricsRecorder().RecordSessionCreated()

	// Set session cookie
	s.setSessionCookie(w, r, token)

	// Check entitlements if configured
	if s.entitlementStore != nil {
		entitlementResult, err := s.entitlementStore.Lookup(session.Subject)
		if err != nil {
			// ErrEntitlementNotFound means user is not authorized
			if errors.Is(err, domain.ErrEntitlementNotFound) {
				s.handleDenied(w, r, session.Subject)
				return nil
			}
			// Other errors are unexpected
			s.getLogger().Error("entitlement lookup failed",
				zap.Error(err),
				zap.String("subject", session.Subject))
			s.renderAppError(w, r, domain.ServiceError("Failed to check entitlements"))
			return err
		}

		// Check require_entitlement if configured
		if s.RequireEntitlement != "" {
			hasRole := false
			for _, role := range entitlementResult.Roles {
				if role == s.RequireEntitlement {
					hasRole = true
					break
				}
			}
			if !hasRole {
				s.handleDenied(w, r, session.Subject)
				return nil
			}
		}
	}

	// Redirect to relay state or default page
	relayState := ValidateRelayState(r.FormValue("RelayState"))
	http.Redirect(w, r, relayState, http.StatusFound)
	return nil
}

// selectIdPRequest is the JSON request body for POST /saml/api/select.
type selectIdPRequest struct {
	EntityID  string `json:"entity_id"`
	ReturnURL string `json:"return_url"`
	Remember  bool   `json:"remember"` // Explicit opt-in required for remember cookie
}

// handleSelectIdP handles POST /saml/api/select to start SAML auth with a selected IdP.
func (s *SAMLDisco) handleSelectIdP(w http.ResponseWriter, r *http.Request) error {
	// Parse JSON request body
	var req selectIdPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.renderAppError(w, r, domain.BadRequestError("Request body is invalid"))
		return nil
	}

	// Validate entity_id is provided
	if req.EntityID == "" {
		s.renderAppError(w, r, domain.BadRequestError("entity_id is required"))
		return nil
	}

	// Look up IdP in metadata store
	if s.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idp, err := s.metadataStore.GetIdP(req.EntityID)
	if err != nil {
		s.getLogger().Debug("idp not found",
			zap.String("entity_id", req.EntityID),
			zap.Error(err),
		)
		s.renderAppError(w, r, domain.IdPNotFoundError(req.EntityID))
		return nil
	}

	s.getLogger().Info("idp selected for authentication",
		zap.String("entity_id", req.EntityID),
	)

	// Only remember the selected IdP if explicitly requested (BREAKING CHANGE)
	if req.Remember {
		s.setRememberIdPCookie(w, r, req.EntityID)
	}

	// Check SAML service is configured
	if s.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	// Determine RelayState (return URL after authentication)
	relayState := req.ReturnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	// Determine if forceAuthn is needed based on return URL path
	opts := &domain.AuthnOptions{
		ForceAuthn: s.ForceAuthn || MatchesForceAuthnPath(relayState, s.ForceAuthnPaths),
	}

	// Compute ACS URL and start SAML auth
	acsURL := s.resolveAcsURL(r)
	redirectURL, err := s.samlService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return nil
	}

	// Return JSON with redirect URL (instead of 302 which causes fetch issues)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": redirectURL.String(),
	})
	return nil
}

// sessionInfoResponse is the JSON response for GET /saml/api/session.
type sessionInfoResponse struct {
	Authenticated bool              `json:"authenticated"`
	Subject       string            `json:"subject,omitempty"`
	IdPEntityID   string            `json:"idp_entity_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// handleDiscoveryUI handles GET /saml/disco and serves the IdP selection page.
// If only one IdP is configured, it auto-redirects to that IdP.
func (s *SAMLDisco) handleDiscoveryUI(w http.ResponseWriter, r *http.Request) error {
	if s.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idps, err := s.metadataStore.ListIdPs("")
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	// Get return_url from query param (where to redirect after auth)
	returnURL := ValidateRelayState(r.URL.Query().Get("return_url"))

	// Auto-redirect if only one IdP
	if len(idps) == 1 && s.samlService != nil {
		idp := &idps[0]
		acsURL := s.resolveAcsURL(r)

		// Determine if forceAuthn is needed based on return URL path
		opts := &domain.AuthnOptions{
			ForceAuthn: s.ForceAuthn || MatchesForceAuthnPath(returnURL, s.ForceAuthnPaths),
		}

		redirectURL, err := s.samlService.StartAuthWithOptions(idp, acsURL, returnURL, opts)
		if err != nil {
			s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
			return nil
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return nil
	}

	// Serve discovery UI HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.renderDiscoveryHTML(w, r, idps, returnURL)
}

// getDefaultLanguage returns the configured default language, falling back to "en".
func (s *SAMLDisco) getDefaultLanguage() string {
	if s.DefaultLanguage != "" {
		return s.DefaultLanguage
	}
	return "en"
}

// getLogger returns the logger, or a no-op logger if not set.
// This allows tests to run without calling Provision().
func (s *SAMLDisco) getLogger() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	return zap.NewNop()
}

// getMetricsRecorder returns the metrics recorder, or a no-op recorder if not set.
// This allows tests to run without calling Provision().
func (s *SAMLDisco) getMetricsRecorder() ports.MetricsRecorder {
	if s.metricsRecorder != nil {
		return s.metricsRecorder
	}
	return metrics.NewNoopMetricsRecorder()
}

// handleSessionInfo handles GET /saml/api/session and returns current session info.
func (s *SAMLDisco) handleSessionInfo(w http.ResponseWriter, r *http.Request) error {
	response := sessionInfoResponse{Authenticated: false}

	// Try to get session from cookie
	if s.sessionStore != nil {
		cookie, err := r.Cookie(s.SessionCookieName)
		if err == nil && cookie.Value != "" {
			session, err := s.sessionStore.Get(cookie.Value)
			if err == nil && session != nil {
				response.Authenticated = true
				response.Subject = session.Subject
				response.IdPEntityID = session.IdPEntityID
				response.Attributes = session.Attributes
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

func (s *SAMLDisco) handleHealth(w http.ResponseWriter, r *http.Request) error {
	if s.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("metadata store not configured"))
		return nil
	}
	health := s.metadataStore.Health()
	resp := HealthResponse{
		Version:        getVersion(),
		GitCommit:      getGitCommit(),
		BuildTime:      getBuildTime(),
		MetadataHealth: health,
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(resp)
}

func (s *SAMLDisco) handleLogoEndpoint(w http.ResponseWriter, r *http.Request) error {
	// Extract entityID from path: /saml/api/logo/{entityID}
	entityID := strings.TrimPrefix(r.URL.Path, "/saml/api/logo/")
	entityID, err := url.PathUnescape(entityID)
	if err != nil {
		http.Error(w, "invalid entity ID", http.StatusBadRequest)
		return nil
	}

	if s.logoStore == nil {
		http.Error(w, "logo store not configured", http.StatusInternalServerError)
		return nil
	}

	logo, err := s.logoStore.Get(entityID)
	if err != nil {
		http.Error(w, "logo not found", http.StatusNotFound)
		return nil
	}

	w.Header().Set("Content-Type", logo.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=86400") // 1 day
	w.Write(logo.Data)
	return nil
}

// idpListResponse is the JSON response for GET /saml/api/idps.
type idpListResponse struct {
	IdPs          []domain.IdPInfo `json:"idps"`
	PinnedIdPs    []domain.IdPInfo `json:"pinned_idps,omitempty"`
	RememberedIdP string           `json:"remembered_idp_id,omitempty"`
}

// handleListIdPs handles GET /saml/api/idps and returns available IdPs as JSON.
// Supports optional ?q=search query parameter to filter IdPs.
// Pinned IdPs are separated into their own list and filtered from the main list.
func (s *SAMLDisco) handleListIdPs(w http.ResponseWriter, r *http.Request) error {
	if s.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	// Get optional search filter from query parameter
	filter := r.URL.Query().Get("q")

	idps, err := s.metadataStore.ListIdPs(filter)
	if err != nil {
		s.getLogger().Error("failed to list idps",
			zap.Error(err),
		)
		s.renderAppError(w, r, domain.ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	// Return empty array instead of null for empty list
	if idps == nil {
		idps = []domain.IdPInfo{}
	}

	s.getLogger().Debug("idp list requested",
		zap.String("filter", filter),
		zap.Int("result_count", len(idps)),
	)

	// Localize IdPs based on Accept-Language header
	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	idps = localizeIdPList(idps, langPrefs, s.getDefaultLanguage())

	// Separate pinned IdPs from the main list
	pinnedIdPs, filteredIdPs := s.separatePinnedIdPs(idps)

	response := idpListResponse{
		IdPs:          filteredIdPs,
		PinnedIdPs:    pinnedIdPs,
		RememberedIdP: s.getRememberIdPCookie(r),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// separatePinnedIdPs separates configured pinned IdPs from the main list.
// Returns (pinnedIdPs, remainingIdPs). Pinned IdPs are returned in the order
// specified in the configuration, not in their original order in the list.
func (s *SAMLDisco) separatePinnedIdPs(idps []domain.IdPInfo) ([]domain.IdPInfo, []domain.IdPInfo) {
	return domain.SeparatePinnedIdPs(idps, s.PinnedIdPs)
}

// handleLogout handles the logout endpoint by clearing the session cookie
// and redirecting to the return_to URL or root.
// If the IdP supports SLO, it redirects to IdP SLO instead of just clearing the cookie.
func (s *SAMLDisco) handleLogout(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		// Fall back to local-only logout
		s.clearSessionCookies(w, r)
		returnTo := ValidateRelayState(r.URL.Query().Get("return_to"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	session := GetSession(r)
	returnTo := ValidateRelayState(r.URL.Query().Get("return_to"))

	// If we have a session, try SP-initiated SLO
	if session != nil {
		idp, err := s.metadataStore.GetIdP(session.IdPEntityID)
		if err == nil && idp != nil && idp.SLOURL != "" {
			// IdP supports SLO - redirect to IdP SLO
			sloURL := s.resolveSLOURL(r)
			logoutURL, err := s.samlService.CreateLogoutRequest(session, idp, sloURL, returnTo)
			if err == nil {
				http.Redirect(w, r, logoutURL.String(), http.StatusFound)
				return nil
			}
			// If SLO fails, fall through to local-only logout
			s.getLogger().Warn("failed to create logout request, falling back to local logout",
				zap.Error(err),
			)
		}
	}

	// Fall back to local-only logout (no SLO or SLO failed)
	s.clearSessionCookies(w, r)
	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

// handleSLO handles the Single Logout endpoint.
// It processes both SP-initiated (SAMLResponse) and IdP-initiated (SAMLRequest) logout flows.
func (s *SAMLDisco) handleSLO(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	sloURL := s.resolveSLOURL(r)

	// Check if this is a LogoutResponse (SP-initiated return) or LogoutRequest (IdP-initiated)
	samlResponse := r.URL.Query().Get("SAMLResponse")
	samlRequest := r.URL.Query().Get("SAMLRequest")

	if samlResponse != "" {
		// SP-initiated: IdP is redirecting back with LogoutResponse
		// Get IdP from session or metadata
		session := GetSession(r)
		if session == nil {
			// No session, just redirect
			returnTo := ValidateRelayState(r.URL.Query().Get("RelayState"))
			http.Redirect(w, r, returnTo, http.StatusFound)
			return nil
		}

		idp, err := s.metadataStore.GetIdP(session.IdPEntityID)
		if err != nil {
			s.renderAppError(w, r, domain.ServiceError("Failed to get IdP metadata"))
			return nil
		}

		// Validate LogoutResponse
		err = s.samlService.HandleLogoutResponse(r, sloURL, idp)
		if err != nil {
			s.getLogger().Warn("logout response validation failed",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
			)
			// Continue with logout anyway
		}

		// Clear session
		http.SetCookie(w, &http.Cookie{
			Name:     s.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		s.clearRememberIdPCookie(w, r)

		// Redirect to return_to or root
		returnTo := ValidateRelayState(r.URL.Query().Get("RelayState"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	if samlRequest != "" {
		// IdP-initiated: IdP is sending LogoutRequest
		// Get IdP from request (would need to parse request to get entity ID)
		// For now, try to get from first available IdP
		idps, err := s.metadataStore.ListIdPs("")
		if err != nil || len(idps) == 0 {
			s.renderAppError(w, r, domain.ConfigError("No identity provider is configured"))
			return nil
		}
		idp := &idps[0]

		// Parse LogoutRequest
		result, err := s.samlService.HandleLogoutRequest(r, sloURL, idp)
		if err != nil {
			s.renderAppError(w, r, domain.AuthError("Invalid logout request", err))
			return nil
		}

		// Clear session for the user (would match by NameID from result)
		http.SetCookie(w, &http.Cookie{
			Name:     s.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		s.clearRememberIdPCookie(w, r)

		// Send LogoutResponse back to IdP
		responseURL, err := s.samlService.CreateLogoutResponse(result.RequestID, idp, sloURL, "")
		if err != nil {
			s.renderAppError(w, r, domain.ServiceError("Failed to create logout response"))
			return nil
		}

		http.Redirect(w, r, responseURL.String(), http.StatusFound)
		return nil
	}

	// Neither SAMLRequest nor SAMLResponse present
	s.renderAppError(w, r, domain.AuthError("Missing SAMLRequest or SAMLResponse", nil))
	return nil
}

// ParseDuration parses a duration string, supporting "d" suffix for days.
// Examples: "30d" (30 days), "8h" (8 hours), "1h30m" (1.5 hours)
// Exported for testing purposes.
func ParseDuration(s string) (time.Duration, error) {
	// Handle day suffix (not supported by time.ParseDuration)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var d int64
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, fmt.Errorf("invalid day format: %s", s)
		}
		// Prevent integer overflow: max safe days is ~106,751 (~292 years)
		// time.Duration is int64 nanoseconds, 24*time.Hour = 86,400,000,000,000 ns
		// Max int64 / (24*time.Hour) ≈ 106,751
		if d < 0 || d > 106751 {
			return 0, fmt.Errorf("day value out of range: %s (max 106751 days)", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// ValidateRelayState ensures the RelayState is a safe relative path.
// Returns "/" for any invalid, absolute, or potentially dangerous URLs.
// This prevents open redirect vulnerabilities.
// Exported for testing purposes.
func ValidateRelayState(relayState string) string {
	// Empty or whitespace-only defaults to root
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return "/"
	}

	// Must start with single forward slash (relative path)
	// Reject protocol-relative URLs (//evil.com)
	if !strings.HasPrefix(relayState, "/") || strings.HasPrefix(relayState, "//") {
		return "/"
	}

	// Parse to detect schemes and other tricks
	parsed, err := url.Parse(relayState)
	if err != nil {
		return "/"
	}

	// Reject if it has a scheme (http:, javascript:, data:, etc.)
	if parsed.Scheme != "" {
		return "/"
	}

	// Reject if it has a host (shouldn't happen with leading / but be safe)
	if parsed.Host != "" {
		return "/"
	}

	// Reject paths with newlines (header injection)
	if strings.ContainsAny(relayState, "\r\n") {
		return "/"
	}

	// Check for encoded characters that could bypass validation
	// Decode and re-check for protocol-relative URLs
	decoded, err := url.QueryUnescape(relayState)
	if err != nil {
		return "/"
	}
	if strings.HasPrefix(decoded, "//") {
		return "/"
	}

	return relayState
}

// ValidateDenyRedirect validates a deny redirect URL.
// Returns the URL if valid, empty string if invalid.
// Allows relative paths or absolute HTTPS URLs.
// Empty string is valid (means use 403, not redirect).
// This prevents open redirect vulnerabilities.
// Exported for testing purposes.
func ValidateDenyRedirect(redirectURL string) string {
	// Empty string is valid (means use 403, not redirect)
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" {
		return ""
	}

	// Parse to detect schemes and other tricks
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	// If it has a scheme, must be https
	if parsed.Scheme != "" {
		if parsed.Scheme != "https" {
			return ""
		}
		// Must have a host for absolute URLs
		if parsed.Host == "" {
			return ""
		}
		return redirectURL
	}

	// No scheme means relative path - validate like RelayState
	// Must start with single forward slash (relative path)
	// Reject protocol-relative URLs (//evil.com)
	if !strings.HasPrefix(redirectURL, "/") || strings.HasPrefix(redirectURL, "//") {
		return ""
	}

	// Reject if parsed URL has a host (shouldn't happen with leading / but be safe)
	if parsed.Host != "" {
		return ""
	}

	// Reject paths with newlines (header injection)
	if strings.ContainsAny(redirectURL, "\r\n") {
		return ""
	}

	// Check for encoded characters that could bypass validation
	// Decode and re-check for protocol-relative URLs
	decoded, err := url.QueryUnescape(redirectURL)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(decoded, "//") {
		return ""
	}

	return redirectURL
}

// applyCORSHeaders sets CORS headers if the request origin is allowed.
// Returns true if CORS headers were applied.
func (s *SAMLDisco) applyCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	if len(s.CORSAllowedOrigins) == 0 {
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}

	// Check if origin is allowed
	allowed := false
	responseOrigin := ""

	if len(s.CORSAllowedOrigins) == 1 && s.CORSAllowedOrigins[0] == "*" {
		allowed = true
		responseOrigin = "*"
	} else {
		for _, o := range s.CORSAllowedOrigins {
			if o == origin {
				allowed = true
				responseOrigin = origin
				break
			}
		}
	}

	if !allowed {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", responseOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if s.CORSAllowCredentials && responseOrigin != "*" {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	return true
}

// SetMetadataStore sets the metadata store for testing.
func (s *SAMLDisco) SetMetadataStore(store ports.MetadataStore) {
	s.metadataStore = store
}

// SetSAMLService sets the SAML service for testing.
func (s *SAMLDisco) SetSAMLService(service *SAMLService) {
	s.samlService = service
}

// SetSessionStore sets the session store for testing.
func (s *SAMLDisco) SetSessionStore(store ports.SessionStore) {
	s.sessionStore = store
}

// SetEntitlementStore sets the entitlement store for testing.
func (s *SAMLDisco) SetEntitlementStore(store ports.EntitlementStore) {
	s.entitlementStore = store
}

// SetTemplateRenderer sets the template renderer for testing.
func (s *SAMLDisco) SetTemplateRenderer(renderer *TemplateRenderer) {
	s.templateRenderer = renderer
}

// SetRememberIdPDuration sets the remember IdP duration for testing.
func (s *SAMLDisco) SetRememberIdPDuration(d time.Duration) {
	s.rememberIdPDuration = d
}

// SetMetricsRecorder sets the metrics recorder for testing.
func (s *SAMLDisco) SetMetricsRecorder(recorder ports.MetricsRecorder) {
	s.metricsRecorder = recorder
}

// SetRegistry sets the SP config registry for testing.
func (s *SAMLDisco) SetRegistry(registry *SPConfigRegistry) {
	s.registry = registry
}

// GetRegistry returns the SP config registry for testing.
func (s *SAMLDisco) GetRegistry() *SPConfigRegistry {
	return s.registry
}

// initMetricsRecorder initializes the metrics recorder based on configuration.
func (s *SAMLDisco) initMetricsRecorder() {
	if s.MetricsEnabled {
		s.metricsRecorder = metrics.NewPrometheusMetricsRecorder()
	} else {
		s.metricsRecorder = metrics.NewNoopMetricsRecorder()
	}
}

// localizeIdPList applies localization to a slice of IdPInfo based on
// language preferences.
func localizeIdPList(idps []domain.IdPInfo, prefs []string, defaultLang string) []domain.IdPInfo {
	if len(idps) == 0 {
		return idps
	}
	localized := make([]domain.IdPInfo, len(idps))
	for i, idp := range idps {
		localized[i] = domain.LocalizeIdPInfo(idp, prefs, defaultLang)
	}
	return localized
}

// ParseAcceptLanguage parses the Accept-Language header and returns
// language tags sorted by quality value (highest first).
// For language tags with region (e.g., "en-US"), the base language
// is also included (e.g., "en") as a fallback.
// Exported for testing purposes.
func ParseAcceptLanguage(header string) []string {
	if header == "" {
		return []string{}
	}

	type langQ struct {
		lang string
		q    float64
	}

	var langs []langQ

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lang := part
		q := 1.0

		if idx := strings.Index(part, ";"); idx != -1 {
			lang = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if parsed, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					q = parsed
				}
			}
		}

		// Skip empty language strings
		if lang == "" {
			continue
		}

		if q > 0 {
			langs = append(langs, langQ{lang: lang, q: q})
			// Add base language for regional variants (en-US -> en)
			if idx := strings.Index(lang, "-"); idx != -1 {
				base := lang[:idx]
				langs = append(langs, langQ{lang: base, q: q - 0.0001}) // Slightly lower
			}
		}
	}

	// Sort by quality descending
	sort.Slice(langs, func(i, j int) bool {
		return langs[i].q > langs[j].q
	})

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, lq := range langs {
		if !seen[lq.lang] {
			seen[lq.lang] = true
			result = append(result, lq.lang)
		}
	}

	return result
}

// Version getters - these are set via ldflags in the root package
// We access them via a function pointer to avoid import cycles
var (
	getVersion   = func() string { return "dev" }
	getGitCommit = func() string { return "" }
	getBuildTime = func() string { return "" }
)

// SetVersionGetters sets the version getter functions.
// Called from root package init to inject version info.
func SetVersionGetters(version, gitCommit, buildTime func() string) {
	getVersion = version
	getGitCommit = gitCommit
	getBuildTime = buildTime
}

// MatchesForceAuthnPath checks if the request path matches any force_authn_paths pattern.
// Patterns support wildcard suffix (e.g., "/admin/*" matches "/admin/settings").
// Returns true if the path matches any pattern, false otherwise.
// Exported for testing purposes.
func MatchesForceAuthnPath(requestPath string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(requestPath, prefix+"/") {
				return true
			}
		} else if pattern == requestPath {
			return true
		}
	}
	return false
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

// Interface guards
var (
	_ caddy.Module                = (*SAMLDisco)(nil)
	_ caddy.Provisioner           = (*SAMLDisco)(nil)
	_ caddy.Validator             = (*SAMLDisco)(nil)
	_ caddy.CleanerUpper          = (*SAMLDisco)(nil)
	_ caddyhttp.MiddlewareHandler = (*SAMLDisco)(nil)
	_ caddyfile.Unmarshaler       = (*SAMLDisco)(nil)
)
