package caddy

import (
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ParseCaddyfile sets up the handler from Caddyfile tokens.
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
//	    background_refresh
//	    session_cookie_name <name>
//	    session_duration <duration>
//	    templates_dir <path>
//	    login_redirect <url>
//	    idp_filter <pattern>
//	    registration_authority_filter <pattern>
//	    verify_metadata_signature
//	    metadata_signing_cert <path>
//	    sign_metadata
//	    attribute_headers {
//	        <saml_attribute> <header_name> [<separator>]
//	    }
//	}
func ParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(h.Dispenser)
	return &s, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (s *SAMLDisco) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "sp":
			// Parse nested SP block for multi-SP mode
			if !d.NextArg() {
				return d.ArgErr()
			}
			hostname := d.Val()

			spCfg := &SPConfig{Hostname: hostname}
			// Parse nested config block
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				if err := s.parseSPConfigField(d, spCfg, nesting); err != nil {
					return err
				}
			}
			s.SPConfigs = append(s.SPConfigs, spCfg)

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

		case "background_refresh":
			s.BackgroundRefresh = true

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

		case "registration_authority_filter":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.RegistrationAuthorityFilter = d.Val()

		case "discovery_template":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.DiscoveryTemplate = d.Val()

		case "service_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.ServiceName = d.Val()

		case "pinned_idps":
			s.PinnedIdPs = d.RemainingArgs()
			if len(s.PinnedIdPs) == 0 {
				return d.ArgErr()
			}

		case "alt_login":
			args := d.RemainingArgs()
			if len(args) < 2 {
				return d.ArgErr()
			}
			s.AltLogins = append(s.AltLogins, AltLoginConfig{
				URL:   args[0],
				Label: args[1],
			})

		case "cors_origins":
			s.CORSAllowedOrigins = d.RemainingArgs()
			if len(s.CORSAllowedOrigins) == 0 {
				return d.ArgErr()
			}

		case "cors_allow_credentials":
			s.CORSAllowCredentials = true

		case "default_language":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.DefaultLanguage = d.Val()

		case "verify_metadata_signature":
			s.VerifyMetadataSignature = true

		case "metadata_signing_cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.MetadataSigningCert = d.Val()

		case "sign_metadata":
			s.SignMetadata = true

		case "metrics":
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch d.Val() {
			case "enabled", "on":
				s.MetricsEnabled = true
			case "disabled", "off":
				s.MetricsEnabled = false
			default:
				return d.Errf("metrics must be 'enabled' or 'off', got %q", d.Val())
			}

		case "attribute_headers":
			// Parse the attribute_headers block
			// Syntax:
			//   attribute_headers {
			//       <saml_attribute> <header_name> [<separator>]
			//   }
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				args := []string{d.Val()}
				args = append(args, d.RemainingArgs()...)

				if len(args) < 2 || len(args) > 3 {
					return d.Errf("attribute_headers: expected 2-3 arguments (saml_attribute header_name [separator]), got %d", len(args))
				}

				mapping := AttributeMapping{
					SAMLAttribute: args[0],
					HeaderName:    args[1],
				}
				if len(args) == 3 {
					mapping.Separator = args[2]
				}

				// Validate header name at parse time
				if !IsValidHeaderName(mapping.HeaderName) {
					return d.Errf("attribute_headers: header name %q must start with X- and contain only A-Za-z0-9-", mapping.HeaderName)
				}

				s.AttributeHeaders = append(s.AttributeHeaders, mapping)
			}

		case "strip_attribute_headers":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := strings.ToLower(d.Val())
			switch val {
			case "on", "true", "enabled":
				s.StripAttributeHeaders = boolPtr(true)
			case "off", "false", "disabled":
				s.StripAttributeHeaders = boolPtr(false)
			default:
				return d.Errf("strip_attribute_headers must be on/off, got %q", d.Val())
			}

		case "header_prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.HeaderPrefix = d.Val()

		case "force_authn":
			s.ForceAuthn = true

		case "force_authn_paths":
			s.ForceAuthnPaths = d.RemainingArgs()
			if len(s.ForceAuthnPaths) == 0 {
				return d.Err("force_authn_paths requires at least one path pattern")
			}

		case "authn_context":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			s.AuthnContext = append(s.AuthnContext, args...)

		case "authn_context_comparison":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.AuthnContextComparison = d.Val()

		default:
			return d.Errf("unrecognized subdirective: %s", d.Val())
		}
	}

	s.Config.SetDefaults()
	return nil
}

// parseSPConfigField parses a single field within an SP config block.
func (s *SAMLDisco) parseSPConfigField(d *caddyfile.Dispenser, spCfg *SPConfig, nesting int) error {
	switch d.Val() {
	case "entity_id":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.EntityID = d.Val()

	case "metadata_url":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.MetadataURL = d.Val()

	case "metadata_file":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.MetadataFile = d.Val()

	case "cert_file":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.CertFile = d.Val()

	case "key_file":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.KeyFile = d.Val()

	case "acs_url":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.AcsURL = d.Val()

	case "metadata_refresh_interval":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.MetadataRefreshInterval = d.Val()

	case "background_refresh":
		spCfg.BackgroundRefresh = true

	case "session_cookie_name":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.SessionCookieName = d.Val()

	case "session_duration":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.SessionDuration = d.Val()

	case "templates_dir":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.TemplatesDir = d.Val()

	case "login_redirect":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.LoginRedirect = d.Val()

	case "idp_filter":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.IdPFilter = d.Val()

	case "registration_authority_filter":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.RegistrationAuthorityFilter = d.Val()

	case "discovery_template":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.DiscoveryTemplate = d.Val()

	case "service_name":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.ServiceName = d.Val()

	case "pinned_idps":
		spCfg.PinnedIdPs = d.RemainingArgs()
		if len(spCfg.PinnedIdPs) == 0 {
			return d.ArgErr()
		}

	case "alt_login":
		args := d.RemainingArgs()
		if len(args) < 2 {
			return d.ArgErr()
		}
		spCfg.AltLogins = append(spCfg.AltLogins, AltLoginConfig{
			URL:   args[0],
			Label: args[1],
		})

	case "cors_origins":
		spCfg.CORSAllowedOrigins = d.RemainingArgs()
		if len(spCfg.CORSAllowedOrigins) == 0 {
			return d.ArgErr()
		}

	case "cors_allow_credentials":
		spCfg.CORSAllowCredentials = true

	case "default_language":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.DefaultLanguage = d.Val()

	case "verify_metadata_signature":
		spCfg.VerifyMetadataSignature = true

	case "metadata_signing_cert":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.MetadataSigningCert = d.Val()

	case "sign_metadata":
		spCfg.SignMetadata = true

	case "metrics":
		if !d.NextArg() {
			return d.ArgErr()
		}
		switch d.Val() {
		case "enabled", "on":
			spCfg.MetricsEnabled = true
		case "disabled", "off":
			spCfg.MetricsEnabled = false
		default:
			return d.Errf("metrics must be 'enabled' or 'off', got %q", d.Val())
		}

	case "attribute_headers":
		// Parse the attribute_headers block
		for attrNesting := d.Nesting(); d.NextBlock(attrNesting); {
			args := []string{d.Val()}
			args = append(args, d.RemainingArgs()...)

			if len(args) < 2 || len(args) > 3 {
				return d.Errf("attribute_headers: expected 2-3 arguments (saml_attribute header_name [separator]), got %d", len(args))
			}

			mapping := AttributeMapping{
				SAMLAttribute: args[0],
				HeaderName:    args[1],
			}
			if len(args) == 3 {
				mapping.Separator = args[2]
			}

			// Validate header name at parse time
			if !IsValidHeaderName(mapping.HeaderName) {
				return d.Errf("attribute_headers: header name %q must start with X- and contain only A-Za-z0-9-", mapping.HeaderName)
			}

			spCfg.AttributeHeaders = append(spCfg.AttributeHeaders, mapping)
		}

	case "strip_attribute_headers":
		if !d.NextArg() {
			return d.ArgErr()
		}
		val := strings.ToLower(d.Val())
		switch val {
		case "on", "true", "enabled":
			spCfg.StripAttributeHeaders = boolPtr(true)
		case "off", "false", "disabled":
			spCfg.StripAttributeHeaders = boolPtr(false)
		default:
			return d.Errf("strip_attribute_headers must be on/off, got %q", d.Val())
		}

	case "header_prefix":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.HeaderPrefix = d.Val()

	case "force_authn":
		spCfg.ForceAuthn = true

	case "force_authn_paths":
		spCfg.ForceAuthnPaths = d.RemainingArgs()
		if len(spCfg.ForceAuthnPaths) == 0 {
			return d.Err("force_authn_paths requires at least one path pattern")
		}

	case "authn_context":
		args := d.RemainingArgs()
		if len(args) == 0 {
			return d.ArgErr()
		}
		spCfg.AuthnContext = append(spCfg.AuthnContext, args...)

	case "authn_context_comparison":
		if !d.NextArg() {
			return d.ArgErr()
		}
		spCfg.AuthnContextComparison = d.Val()

	default:
		return d.Errf("unrecognized subdirective in sp block: %s", d.Val())
	}
	return nil
}
