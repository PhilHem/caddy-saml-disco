package caddysamldisco

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// parseCaddyfile sets up the handler from Caddyfile tokens.
//
// Syntax:
//
//	saml_disco {
//	    entity_id <entity_id>
//	    metadata_url <url>
//	    metadata_file <path>
//	    cert_file <path>
//	    key_file <path>
//	    acs_url <url>
//	    metadata_refresh_interval <duration>
//	    session_cookie_name <name>
//	    session_duration <duration>
//	    templates_dir <path>
//	    login_redirect <url>
//	    idp_filter <pattern>
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(h.Dispenser)
	return &s, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (s *SAMLDisco) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "entity_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.EntityID = d.Val()

		case "metadata_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.MetadataURL = d.Val()

		case "metadata_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.MetadataFile = d.Val()

		case "cert_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.CertFile = d.Val()

		case "key_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.KeyFile = d.Val()

		case "acs_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.AcsURL = d.Val()

		case "metadata_refresh_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.MetadataRefreshInterval = d.Val()

		case "session_cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.SessionCookieName = d.Val()

		case "session_duration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.SessionDuration = d.Val()

		case "templates_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.TemplatesDir = d.Val()

		case "login_redirect":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.LoginRedirect = d.Val()

		case "idp_filter":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.IdPFilter = d.Val()

		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	s.Config.SetDefaults()
	return nil
}
