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

const Version = "0.1.0"

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
	metadataStore MetadataStore
	sessionStore  SessionStore
	samlService   *SAMLService
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
			s.redirectToLogin(w, r)
			return nil
		}

		// Validate session token
		session, err := s.sessionStore.Get(cookie.Value)
		if err != nil {
			s.redirectToLogin(w, r)
			return nil
		}

		// Store session in context for downstream handlers
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		r = r.WithContext(ctx)
	}

	// Pass through to next handler
	return next.ServeHTTP(w, r)
}

// redirectToLogin redirects the user to the login page.
// Uses LoginRedirect if configured, otherwise defaults to /saml/disco.
// Includes the original URL as a return_to query parameter.
func (s *SAMLDisco) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/saml/disco"
	if s.LoginRedirect != "" {
		target = s.LoginRedirect
	}

	// Preserve original URL for post-login redirect
	originalURL := r.URL.RequestURI()
	redirectURL, _ := url.Parse(target)
	q := redirectURL.Query()
	q.Set("return_to", originalURL)
	redirectURL.RawQuery = q.Encode()

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
		ExpiresAt:   time.Now().Add(8 * time.Hour), // TODO: use configured duration
	}

	token, err := s.sessionStore.Create(session)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return err
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to relay state or default page
	relayState := r.FormValue("RelayState")
	if relayState == "" {
		relayState = "/"
	}
	http.Redirect(w, r, relayState, http.StatusFound)
	return nil
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
