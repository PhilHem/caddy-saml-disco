// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"fmt"
	"net/http"

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
	// sessionStore  SessionStore
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

	// TODO: Initialize session store
	// TODO: Load SAML SP certificate and key
	return nil
}

// Validate ensures the module's configuration is valid.
func (s *SAMLDisco) Validate() error {
	return s.Config.Validate()
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// TODO: Route SAML endpoints (/saml/acs, /saml/metadata, /saml/disco, /saml/api/*)
	// TODO: Check session for protected routes
	// TODO: Redirect to discovery if no session

	// For now, pass through to next handler
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Module                = (*SAMLDisco)(nil)
	_ caddy.Provisioner           = (*SAMLDisco)(nil)
	_ caddy.Validator             = (*SAMLDisco)(nil)
	_ caddyhttp.MiddlewareHandler = (*SAMLDisco)(nil)
	_ caddyfile.Unmarshaler       = (*SAMLDisco)(nil)
)
