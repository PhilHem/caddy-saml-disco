// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const Version = "0.7.0"

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
	samlService         *SAMLService
	sessionDuration     time.Duration
	rememberIdPDuration time.Duration
	templateRenderer    *TemplateRenderer
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
		renderer, err := NewTemplateRenderer()
		if err != nil {
			return fmt.Errorf("load embedded templates: %w", err)
		}
		s.templateRenderer = renderer
	}

	return nil
}

// Validate ensures the module's configuration is valid.
func (s *SAMLDisco) Validate() error {
	return s.Config.Validate()
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "Metadata store is not configured")
		return
	}
	if s.samlService == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "SAML service is not configured")
		return
	}

	// Get single IdP from metadata store (Phase 1: only one IdP)
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "No identity provider is configured")
		return
	}
	idp := &idps[0]

	// Compute ACS URL and use original URL as RelayState
	acsURL := s.resolveAcsURL(r)
	relayState := r.URL.RequestURI()

	// Generate AuthnRequest and redirect URL
	redirectURL, err := s.samlService.StartAuth(idp, acsURL, relayState)
	if err != nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Authentication Error", "Failed to start authentication")
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleMetadata serves the SP metadata XML.
func (s *SAMLDisco) handleMetadata(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "SAML service is not configured")
		return nil
	}

	acsURL := s.resolveAcsURL(r)
	metadata, err := s.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Service Error", "Failed to generate metadata")
		return err
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
	return nil
}

// handleACS processes the SAML Response from the IdP.
func (s *SAMLDisco) handleACS(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "SAML service is not configured")
		return nil
	}

	// For Phase 1 with single IdP, get the first IdP from metadata store
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "No identity provider is configured")
		return err
	}
	idp := &idps[0]

	acsURL := s.resolveAcsURL(r)
	result, err := s.samlService.HandleACS(r, acsURL, idp)
	if err != nil {
		s.renderHTTPError(w, http.StatusUnauthorized, "Authentication Failed", "SAML authentication failed")
		return nil
	}

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
		s.renderHTTPError(w, http.StatusInternalServerError, "Session Error", "Failed to create session")
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
}

// handleSelectIdP handles POST /saml/api/select to start SAML auth with a selected IdP.
func (s *SAMLDisco) handleSelectIdP(w http.ResponseWriter, r *http.Request) error {
	// Parse JSON request body
	var req selectIdPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.renderHTTPError(w, http.StatusBadRequest, "Invalid Request", "Request body is invalid")
		return nil
	}

	// Validate entity_id is provided
	if req.EntityID == "" {
		s.renderHTTPError(w, http.StatusBadRequest, "Invalid Request", "entity_id is required")
		return nil
	}

	// Look up IdP in metadata store
	if s.metadataStore == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "Metadata store is not configured")
		return nil
	}

	idp, err := s.metadataStore.GetIdP(req.EntityID)
	if err != nil {
		s.renderHTTPError(w, http.StatusNotFound, "IdP Not Found", "The requested identity provider was not found")
		return nil
	}

	// Remember the selected IdP for next time
	s.setRememberIdPCookie(w, r, req.EntityID)

	// Check SAML service is configured
	if s.samlService == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "SAML service is not configured")
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
		s.renderHTTPError(w, http.StatusInternalServerError, "Authentication Error", "Failed to start authentication")
		return nil
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
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
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "Metadata store is not configured")
		return nil
	}

	idps, err := s.metadataStore.ListIdPs("")
	if err != nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Service Error", "Failed to retrieve identity providers")
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
			s.renderHTTPError(w, http.StatusInternalServerError, "Authentication Error", "Failed to start authentication")
			return nil
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return nil
	}

	// Serve discovery UI HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.renderDiscoveryHTML(w, r, idps, returnURL)
}

// renderDiscoveryHTML renders the IdP selection page using the template renderer.
func (s *SAMLDisco) renderDiscoveryHTML(w http.ResponseWriter, r *http.Request, idps []IdPInfo, returnURL string) error {
	return s.templateRenderer.RenderDisco(w, DiscoData{
		IdPs:            idps,
		ReturnURL:       returnURL,
		RememberedIdPID: s.getRememberIdPCookie(r),
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

// idpListResponse is the JSON response for GET /saml/api/idps.
type idpListResponse struct {
	IdPs          []IdPInfo `json:"idps"`
	RememberedIdP string    `json:"remembered_idp_id,omitempty"`
}

// handleListIdPs handles GET /saml/api/idps and returns available IdPs as JSON.
// Supports optional ?q=search query parameter to filter IdPs.
func (s *SAMLDisco) handleListIdPs(w http.ResponseWriter, r *http.Request) error {
	if s.metadataStore == nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Configuration Error", "Metadata store is not configured")
		return nil
	}

	// Get optional search filter from query parameter
	filter := r.URL.Query().Get("q")

	idps, err := s.metadataStore.ListIdPs(filter)
	if err != nil {
		s.renderHTTPError(w, http.StatusInternalServerError, "Service Error", "Failed to retrieve identity providers")
		return nil
	}

	// Return empty array instead of null for empty list
	if idps == nil {
		idps = []IdPInfo{}
	}

	response := idpListResponse{
		IdPs:          idps,
		RememberedIdP: s.getRememberIdPCookie(r),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
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

// Interface guards
var (
	_ caddy.Module                = (*SAMLDisco)(nil)
	_ caddy.Provisioner           = (*SAMLDisco)(nil)
	_ caddy.Validator             = (*SAMLDisco)(nil)
	_ caddyhttp.MiddlewareHandler = (*SAMLDisco)(nil)
	_ caddyfile.Unmarshaler       = (*SAMLDisco)(nil)
	_ SessionStore                = (*CookieSessionStore)(nil)
)
