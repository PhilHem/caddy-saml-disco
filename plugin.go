// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const Version = "0.8.0"

func init() {
	caddy.RegisterModule(SAMLDisco{})
	httpcaddyfile.RegisterHandlerDirective("saml_disco", parseCaddyfile)
}

// SAMLDisco is a Caddy HTTP handler module that provides SAML SP authentication
// with IdP discovery service support.
type SAMLDisco struct {
	// Configuration embedded directly
	Config

	// Runtime state (not serialized)
	metadataStore       MetadataStore
	sessionStore        SessionStore
	logoStore           LogoStore
	samlService         *SAMLService
	sessionDuration     time.Duration
	rememberIdPDuration time.Duration
	templateRenderer    *TemplateRenderer
	logger              *zap.Logger
}

// SetLogoStore sets the logo store. For testing purposes.
func (s *SAMLDisco) SetLogoStore(store LogoStore) {
	s.logoStore = store
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

	s.Config.SetDefaults()

	// Parse refresh interval for metadata cache TTL
	refreshInterval, err := time.ParseDuration(s.MetadataRefreshInterval)
	if err != nil {
		return fmt.Errorf("parse metadata refresh interval: %w", err)
	}

	// Build metadata store options
	var metadataOpts []MetadataOption
	if s.IdPFilter != "" {
		metadataOpts = append(metadataOpts, WithIdPFilter(s.IdPFilter))
	}

	// Configure signature verification if enabled
	if s.VerifyMetadataSignature {
		certs, err := LoadSigningCertificates(s.MetadataSigningCert)
		if err != nil {
			return fmt.Errorf("load metadata signing certificate: %w", err)
		}
		verifier := NewXMLDsigVerifierWithCerts(certs)
		metadataOpts = append(metadataOpts, WithSignatureVerifier(verifier))
		s.logger.Info("metadata signature verification enabled",
			zap.String("cert_file", s.MetadataSigningCert),
			zap.Int("cert_count", len(certs)))
	}

	// Initialize metadata store based on config
	if s.MetadataFile != "" {
		store := NewFileMetadataStore(s.MetadataFile, metadataOpts...)
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from file: %w", err)
		}
		s.metadataStore = store
	} else if s.MetadataURL != "" {
		store := NewURLMetadataStore(s.MetadataURL, refreshInterval, metadataOpts...)
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from URL: %w", err)
		}
		s.metadataStore = store
	}

	// Initialize logo store if metadata store is configured
	if s.metadataStore != nil {
		s.logoStore = NewCachingLogoStore(s.metadataStore, nil)
	}

	// Initialize session store and SAML service if key file is configured
	if s.KeyFile != "" {
		privateKey, err := LoadPrivateKey(s.KeyFile)
		if err != nil {
			return fmt.Errorf("load SP private key: %w", err)
		}

		duration, err := time.ParseDuration(s.SessionDuration)
		if err != nil {
			return fmt.Errorf("parse session duration: %w", err)
		}

		s.sessionStore = NewCookieSessionStore(privateKey, duration)
		s.sessionDuration = duration

		// Initialize SAML service if certificate is also configured
		if s.CertFile != "" {
			certificate, err := LoadCertificate(s.CertFile)
			if err != nil {
				return fmt.Errorf("load SP certificate: %w", err)
			}
			s.samlService = NewSAMLService(s.EntityID, privateKey, certificate)
		}
	}

	// Parse remember IdP duration
	if s.RememberIdPDuration != "" {
		rememberDur, err := parseDuration(s.RememberIdPDuration)
		if err != nil {
			return fmt.Errorf("parse remember IdP duration: %w", err)
		}
		s.rememberIdPDuration = rememberDur
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
	s.logger.Info("saml discovery service provisioned",
		zap.String("entity_id", s.EntityID),
		zap.Int("idp_count", idpCount),
		zap.String("version", Version),
	)

	return nil
}

// Validate ensures the module's configuration is valid.
func (s *SAMLDisco) Validate() error {
	return s.Config.Validate()
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
		return s.handleLogoEndpoint(w, r)
	}

	// Route SAML endpoints
	switch r.URL.Path {
	case "/saml/metadata":
		if r.Method == http.MethodGet {
			return s.handleMetadata(w, r)
		}
	case "/saml/acs":
		if r.Method == http.MethodPost {
			return s.handleACS(w, r)
		}
	case "/saml/logout":
		if r.Method == http.MethodGet {
			return s.handleLogout(w, r)
		}
	case "/saml/api/idps":
		if r.Method == http.MethodGet {
			return s.handleListIdPs(w, r)
		}
	case "/saml/api/select":
		if r.Method == http.MethodPost {
			return s.handleSelectIdP(w, r)
		}
	case "/saml/api/session":
		if r.Method == http.MethodGet {
			return s.handleSessionInfo(w, r)
		}
	case "/saml/disco":
		if r.Method == http.MethodGet {
			return s.handleDiscoveryUI(w, r)
		}
	}

	// Check session for protected routes (skip SAML endpoints)
	if s.sessionStore != nil && !strings.HasPrefix(r.URL.Path, "/saml/") {
		cookie, err := r.Cookie(s.SessionCookieName)
		if err != nil || cookie.Value == "" {
			s.redirectToIdP(w, r)
			return nil
		}

		// Validate session token
		session, err := s.sessionStore.Get(cookie.Value)
		if err != nil {
			s.redirectToIdP(w, r)
			return nil
		}

		// Store session in context for downstream handlers
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		r = r.WithContext(ctx)
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

	// Check if required services are configured
	if s.metadataStore == nil {
		s.renderAppError(w, r, ConfigError("Metadata store is not configured"))
		return
	}
	if s.samlService == nil {
		s.renderAppError(w, r, ConfigError("SAML service is not configured"))
		return
	}

	// Get single IdP from metadata store (Phase 1: only one IdP)
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderAppError(w, r, ConfigError("No identity provider is configured"))
		return
	}
	idp := &idps[0]

	// Compute ACS URL and use original URL as RelayState
	acsURL := s.resolveAcsURL(r)
	relayState := r.URL.RequestURI()

	// Generate AuthnRequest and redirect URL
	redirectURL, err := s.samlService.StartAuth(idp, acsURL, relayState)
	if err != nil {
		s.renderAppError(w, r, AuthError("Failed to start authentication", err))
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleMetadata serves the SP metadata XML.
func (s *SAMLDisco) handleMetadata(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderAppError(w, r, ConfigError("SAML service is not configured"))
		return nil
	}

	acsURL := s.resolveAcsURL(r)
	metadata, err := s.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		s.renderAppError(w, r, ServiceError("Failed to generate metadata"))
		return err
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
	return nil
}

// handleACS processes the SAML Response from the IdP.
func (s *SAMLDisco) handleACS(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderAppError(w, r, ConfigError("SAML service is not configured"))
		return nil
	}

	// For Phase 1 with single IdP, get the first IdP from metadata store
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderAppError(w, r, ConfigError("No identity provider is configured"))
		return err
	}
	idp := &idps[0]

	acsURL := s.resolveAcsURL(r)
	result, err := s.samlService.HandleACS(r, acsURL, idp)
	if err != nil {
		s.getLogger().Warn("saml authentication failed",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, AuthError("SAML authentication failed", err))
		return nil
	}

	s.getLogger().Info("saml authentication successful",
		zap.String("subject", result.Subject),
		zap.String("idp_entity_id", result.IdPEntityID),
	)

	// Create session
	session := &Session{
		Subject:     result.Subject,
		Attributes:  result.Attributes,
		IdPEntityID: result.IdPEntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(s.sessionDuration),
	}

	token, err := s.sessionStore.Create(session)
	if err != nil {
		s.renderAppError(w, r, ServiceError("Failed to create session"))
		return err
	}

	// Set session cookie
	s.setSessionCookie(w, r, token)

	// Redirect to relay state or default page
	relayState := validateRelayState(r.FormValue("RelayState"))
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
		s.renderAppError(w, r, BadRequestError("Request body is invalid"))
		return nil
	}

	// Validate entity_id is provided
	if req.EntityID == "" {
		s.renderAppError(w, r, BadRequestError("entity_id is required"))
		return nil
	}

	// Look up IdP in metadata store
	if s.metadataStore == nil {
		s.renderAppError(w, r, ConfigError("Metadata store is not configured"))
		return nil
	}

	idp, err := s.metadataStore.GetIdP(req.EntityID)
	if err != nil {
		s.getLogger().Debug("idp not found",
			zap.String("entity_id", req.EntityID),
			zap.Error(err),
		)
		s.renderAppError(w, r, IdPNotFoundError(req.EntityID))
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
		s.renderAppError(w, r, ConfigError("SAML service is not configured"))
		return nil
	}

	// Determine RelayState (return URL after authentication)
	relayState := req.ReturnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = validateRelayState(relayState)

	// Compute ACS URL and start SAML auth
	acsURL := s.resolveAcsURL(r)
	redirectURL, err := s.samlService.StartAuth(idp, acsURL, relayState)
	if err != nil {
		s.renderAppError(w, r, AuthError("Failed to start authentication", err))
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
		s.renderAppError(w, r, ConfigError("Metadata store is not configured"))
		return nil
	}

	idps, err := s.metadataStore.ListIdPs("")
	if err != nil {
		s.renderAppError(w, r, ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	// Get return_url from query param (where to redirect after auth)
	returnURL := validateRelayState(r.URL.Query().Get("return_url"))

	// Auto-redirect if only one IdP
	if len(idps) == 1 && s.samlService != nil {
		idp := &idps[0]
		acsURL := s.resolveAcsURL(r)
		redirectURL, err := s.samlService.StartAuth(idp, acsURL, returnURL)
		if err != nil {
			s.renderAppError(w, r, AuthError("Failed to start authentication", err))
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

// renderDiscoveryHTML renders the IdP selection page using the template renderer.
func (s *SAMLDisco) renderDiscoveryHTML(w http.ResponseWriter, r *http.Request, idps []IdPInfo, returnURL string) error {
	// Localize IdPs based on Accept-Language header
	langPrefs := parseAcceptLanguage(r.Header.Get("Accept-Language"))
	defaultLang := s.getDefaultLanguage()
	localizedIdPs := localizeIdPList(idps, langPrefs, defaultLang)

	// Separate pinned IdPs from the main list
	pinnedIdPs, filteredIdPs := s.separatePinnedIdPs(localizedIdPs)

	// Get the remembered IdP entity ID
	rememberedIdPID := s.getRememberIdPCookie(r)

	// Look up full IdP info for the remembered IdP (and localize it)
	var rememberedIdP *IdPInfo
	if rememberedIdPID != "" && s.metadataStore != nil {
		if idp, err := s.metadataStore.GetIdP(rememberedIdPID); err == nil {
			localized := LocalizeIdPInfo(*idp, langPrefs, defaultLang)
			rememberedIdP = &localized
		}
	}

	// Convert alt login config to template data
	altLogins := make([]AltLoginOption, len(s.AltLogins))
	for i, alt := range s.AltLogins {
		altLogins[i] = AltLoginOption{URL: alt.URL, Label: alt.Label}
	}

	return s.templateRenderer.RenderDisco(w, DiscoData{
		IdPs:            filteredIdPs,
		PinnedIdPs:      pinnedIdPs,
		ReturnURL:       returnURL,
		RememberedIdPID: rememberedIdPID,
		RememberedIdP:   rememberedIdP,
		AltLogins:       altLogins,
		ServiceName:     s.ServiceName,
	})
}

// renderHTTPError renders an HTML error page with the given status code, title, and message.
// This provides user-friendly error pages instead of plain text http.Error responses.
// Falls back to plain text if template renderer is not configured.
func (s *SAMLDisco) renderHTTPError(w http.ResponseWriter, statusCode int, title, message string) {
	// Fall back to plain text if template renderer is not configured
	if s.templateRenderer == nil {
		http.Error(w, message, statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	// RenderError uses html/template which auto-escapes to prevent XSS
	s.templateRenderer.RenderError(w, ErrorData{
		Title:   title,
		Message: message,
	})
}

// renderAppError renders an AppError as JSON for API endpoints or HTML for others.
// API endpoints are detected by the /saml/api/ path prefix.
func (s *SAMLDisco) renderAppError(w http.ResponseWriter, r *http.Request, err *AppError) {
	statusCode := err.Code.HTTPStatus()

	// API endpoints get JSON responses
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(NewJSONErrorResponse(err))
		return
	}

	// Non-API endpoints get HTML
	s.renderHTTPError(w, statusCode, err.Code.Title(), err.Message)
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
	IdPs          []IdPInfo `json:"idps"`
	PinnedIdPs    []IdPInfo `json:"pinned_idps,omitempty"`
	RememberedIdP string    `json:"remembered_idp_id,omitempty"`
}

// handleListIdPs handles GET /saml/api/idps and returns available IdPs as JSON.
// Supports optional ?q=search query parameter to filter IdPs.
// Pinned IdPs are separated into their own list and filtered from the main list.
func (s *SAMLDisco) handleListIdPs(w http.ResponseWriter, r *http.Request) error {
	if s.metadataStore == nil {
		s.renderAppError(w, r, ConfigError("Metadata store is not configured"))
		return nil
	}

	// Get optional search filter from query parameter
	filter := r.URL.Query().Get("q")

	idps, err := s.metadataStore.ListIdPs(filter)
	if err != nil {
		s.getLogger().Error("failed to list idps",
			zap.Error(err),
		)
		s.renderAppError(w, r, ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	// Return empty array instead of null for empty list
	if idps == nil {
		idps = []IdPInfo{}
	}

	s.getLogger().Debug("idp list requested",
		zap.String("filter", filter),
		zap.Int("result_count", len(idps)),
	)

	// Localize IdPs based on Accept-Language header
	langPrefs := parseAcceptLanguage(r.Header.Get("Accept-Language"))
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
func (s *SAMLDisco) separatePinnedIdPs(idps []IdPInfo) ([]IdPInfo, []IdPInfo) {
	if len(s.PinnedIdPs) == 0 {
		return nil, idps
	}

	// Create a map for quick lookup of pinned entity IDs
	pinnedSet := make(map[string]bool, len(s.PinnedIdPs))
	for _, entityID := range s.PinnedIdPs {
		pinnedSet[entityID] = true
	}

	// Create a map to look up IdP info by entity ID
	idpMap := make(map[string]IdPInfo, len(idps))
	for _, idp := range idps {
		idpMap[idp.EntityID] = idp
	}

	// Build pinned list in configuration order
	var pinnedIdPs []IdPInfo
	for _, entityID := range s.PinnedIdPs {
		if idp, ok := idpMap[entityID]; ok {
			pinnedIdPs = append(pinnedIdPs, idp)
		}
	}

	// Build remaining list (excluding pinned)
	var remainingIdPs []IdPInfo
	for _, idp := range idps {
		if !pinnedSet[idp.EntityID] {
			remainingIdPs = append(remainingIdPs, idp)
		}
	}

	// Ensure we return empty slices instead of nil
	if pinnedIdPs == nil {
		pinnedIdPs = []IdPInfo{}
	}
	if remainingIdPs == nil {
		remainingIdPs = []IdPInfo{}
	}

	return pinnedIdPs, remainingIdPs
}

// handleLogout handles the logout endpoint by clearing the session cookie
// and redirecting to the return_to URL or root.
func (s *SAMLDisco) handleLogout(w http.ResponseWriter, r *http.Request) error {
	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})

	// Clear the remember IdP cookie
	s.clearRememberIdPCookie(w, r)

	// Redirect to return_to or root (validate to prevent open redirect)
	returnTo := validateRelayState(r.URL.Query().Get("return_to"))
	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

// parseDuration parses a duration string, supporting "d" suffix for days.
// Examples: "30d" (30 days), "8h" (8 hours), "1h30m" (1.5 hours)
func parseDuration(s string) (time.Duration, error) {
	// Handle day suffix (not supported by time.ParseDuration)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, fmt.Errorf("invalid day format: %s", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// validateRelayState ensures the RelayState is a safe relative path.
// Returns "/" for any invalid, absolute, or potentially dangerous URLs.
// This prevents open redirect vulnerabilities.
func validateRelayState(relayState string) string {
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

// setSessionCookie sets the session cookie on the response.
func (s *SAMLDisco) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionDuration.Seconds()),
	})
}

// setRememberIdPCookie sets a cookie to remember the user's last-used IdP.
func (s *SAMLDisco) setRememberIdPCookie(w http.ResponseWriter, r *http.Request, entityID string) {
	if s.RememberIdPCookieName == "" || s.rememberIdPDuration == 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.RememberIdPCookieName,
		Value:    entityID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.rememberIdPDuration.Seconds()),
	})
}

// getRememberIdPCookie reads the remembered IdP entity ID from the cookie.
func (s *SAMLDisco) getRememberIdPCookie(r *http.Request) string {
	if s.RememberIdPCookieName == "" {
		return ""
	}
	cookie, err := r.Cookie(s.RememberIdPCookieName)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

// clearRememberIdPCookie deletes the remembered IdP cookie.
func (s *SAMLDisco) clearRememberIdPCookie(w http.ResponseWriter, r *http.Request) {
	if s.RememberIdPCookieName == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.RememberIdPCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
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

// resolveAcsURL computes the ACS URL from the request and configuration.
func (s *SAMLDisco) resolveAcsURL(r *http.Request) *url.URL {
	if s.AcsURL != "" {
		u, _ := url.Parse(s.AcsURL)
		return u
	}

	// Compute from request
	scheme := "https"
	if r.TLS == nil {
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}

	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// SetMetadataStore sets the metadata store for testing.
func (s *SAMLDisco) SetMetadataStore(store MetadataStore) {
	s.metadataStore = store
}

// SetSAMLService sets the SAML service for testing.
func (s *SAMLDisco) SetSAMLService(service *SAMLService) {
	s.samlService = service
}

// SetSessionStore sets the session store for testing.
func (s *SAMLDisco) SetSessionStore(store SessionStore) {
	s.sessionStore = store
}

// SetTemplateRenderer sets the template renderer for testing.
func (s *SAMLDisco) SetTemplateRenderer(renderer *TemplateRenderer) {
	s.templateRenderer = renderer
}

// SetRememberIdPDuration sets the remember IdP duration for testing.
func (s *SAMLDisco) SetRememberIdPDuration(d time.Duration) {
	s.rememberIdPDuration = d
}

// localizeIdPList applies localization to a slice of IdPInfo based on
// language preferences.
func localizeIdPList(idps []IdPInfo, prefs []string, defaultLang string) []IdPInfo {
	if len(idps) == 0 {
		return idps
	}
	localized := make([]IdPInfo, len(idps))
	for i, idp := range idps {
		localized[i] = LocalizeIdPInfo(idp, prefs, defaultLang)
	}
	return localized
}

// parseAcceptLanguage parses the Accept-Language header and returns
// language tags sorted by quality value (highest first).
// For language tags with region (e.g., "en-US"), the base language
// is also included (e.g., "en") as a fallback.
func parseAcceptLanguage(header string) []string {
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
	var result []string
	for _, lq := range langs {
		if !seen[lq.lang] {
			seen[lq.lang] = true
			result = append(result, lq.lang)
		}
	}

	return result
}

// Interface guards
var (
	_ caddy.Module                = (*SAMLDisco)(nil)
	_ caddy.Provisioner           = (*SAMLDisco)(nil)
	_ caddy.Validator             = (*SAMLDisco)(nil)
	_ caddyhttp.MiddlewareHandler = (*SAMLDisco)(nil)
	_ caddyfile.Unmarshaler       = (*SAMLDisco)(nil)
	_ SessionStore                = (*CookieSessionStore)(nil)
)
