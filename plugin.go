// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"context"
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

const Version = "0.4.1"

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
	metadataStore   MetadataStore
	sessionStore    SessionStore
	samlService     *SAMLService
	sessionDuration time.Duration
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

	// Initialize metadata store based on config
	if s.MetadataFile != "" {
		store := NewFileMetadataStore(s.MetadataFile)
		if err := store.Load(); err != nil {
			return fmt.Errorf("load metadata from file: %w", err)
		}
		s.metadataStore = store
	}
	// TODO: Add URL-based metadata loading in Phase 2

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
		// Phase 2: Discovery routes
		// case "/saml/disco":
		// case "/saml/api/idps":
		// case "/saml/api/select":
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

// redirectToIdP redirects the user directly to the IdP for authentication.
// For Phase 1 (single IdP scenario), this bypasses the discovery UI.
// The original URL is passed as RelayState so ACS can redirect back after login.
func (s *SAMLDisco) redirectToIdP(w http.ResponseWriter, r *http.Request) {
	// Check if required services are configured
	if s.metadataStore == nil {
		http.Error(w, "Metadata store not configured", http.StatusInternalServerError)
		return
	}
	if s.samlService == nil {
		http.Error(w, "SAML service not configured", http.StatusInternalServerError)
		return
	}

	// Get single IdP from metadata store (Phase 1: only one IdP)
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		http.Error(w, "No identity provider configured", http.StatusInternalServerError)
		return
	}
	idp := &idps[0]

	// Compute ACS URL and use original URL as RelayState
	acsURL := s.resolveAcsURL(r)
	relayState := r.URL.RequestURI()

	// Generate AuthnRequest and redirect URL
	redirectURL, err := s.samlService.StartAuth(idp, acsURL, relayState)
	if err != nil {
		http.Error(w, "Failed to start authentication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleMetadata serves the SP metadata XML.
func (s *SAMLDisco) handleMetadata(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		http.Error(w, "SAML not configured", http.StatusInternalServerError)
		return nil
	}

	acsURL := s.resolveAcsURL(r)
	metadata, err := s.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		http.Error(w, "Failed to generate metadata", http.StatusInternalServerError)
		return err
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
	return nil
}

// handleACS processes the SAML Response from the IdP.
func (s *SAMLDisco) handleACS(w http.ResponseWriter, r *http.Request) error {
	if s.samlService == nil {
		http.Error(w, "SAML not configured", http.StatusInternalServerError)
		return nil
	}

	// For Phase 1 with single IdP, get the first IdP from metadata store
	idps, err := s.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		http.Error(w, "No IdP configured", http.StatusInternalServerError)
		return err
	}
	idp := &idps[0]

	acsURL := s.resolveAcsURL(r)
	result, err := s.samlService.HandleACS(r, acsURL, idp)
	if err != nil {
		http.Error(w, "SAML authentication failed: "+err.Error(), http.StatusUnauthorized)
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
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return err
	}

	// Set session cookie
	s.setSessionCookie(w, r, token)

	// Redirect to relay state or default page
	relayState := r.FormValue("RelayState")
	if relayState == "" {
		relayState = "/"
	}
	http.Redirect(w, r, relayState, http.StatusFound)
	return nil
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

// Interface guards
var (
	_ caddy.Module                = (*SAMLDisco)(nil)
	_ caddy.Provisioner           = (*SAMLDisco)(nil)
	_ caddy.Validator             = (*SAMLDisco)(nil)
	_ caddyhttp.MiddlewareHandler = (*SAMLDisco)(nil)
	_ caddyfile.Unmarshaler       = (*SAMLDisco)(nil)
	_ SessionStore                = (*CookieSessionStore)(nil)
)
