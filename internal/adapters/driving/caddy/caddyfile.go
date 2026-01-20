package caddy

import (
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
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

		default:
			// Try to parse as a Config directive (single-SP mode)
			handled, err := parseConfigDirective(d, &s.Config)
			if err != nil {
				return err
			}
			if !handled {
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}

	s.Config.SetDefaults()
	return nil
}

// parseSPConfigField parses a single field within an SP config block.
// nesting parameter is kept for API compatibility but unused after refactoring.
func (s *SAMLDisco) parseSPConfigField(d *caddyfile.Dispenser, spCfg *SPConfig, _ int) error {
	handled, err := parseConfigDirective(d, &spCfg.Config)
	if err != nil {
		return err
	}
	if !handled {
		return d.Errf("unrecognized subdirective in sp block: %s", d.Val())
	}
	return nil
}

// parseConfigDirective parses a single Config field directive.
// Returns (true, nil) if the directive was handled successfully.
// Returns (false, nil) if the directive is not a Config field (caller should handle).
// Returns (true, error) if the directive was recognized but had a parsing error.
func parseConfigDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "entity_id":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		entityID := d.Val()
		if err := domain.ValidateEntityID(entityID); err != nil {
			return true, d.Errf("entity_id: %v", err)
		}
		cfg.EntityID = entityID

	case "metadata_url":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		url := d.Val()

		// Create a MetadataSource entry and parse any block options
		src := &MetadataSource{URL: url}

		// Check if there's a nested block with options
		nesting := d.Nesting()
		for d.NextBlock(nesting) {
			switch d.Val() {
			case "idp_filter":
				if !d.NextArg() {
					return true, d.ArgErr()
				}
				src.IdPFilter = d.Val()

			case "refresh_interval":
				if !d.NextArg() {
					return true, d.ArgErr()
				}
				interval, err := parseDuration(d.Val())
				if err != nil {
					return true, d.Errf("refresh_interval: %v", err)
				}
				src.RefreshInterval = interval

			default:
				return true, d.Errf("unrecognized metadata_url block option: %s", d.Val())
			}
		}

		// Always add to MetadataSources for multi-source support
		src.SetDefaults()
		cfg.MetadataSources = append(cfg.MetadataSources, *src)

	case "metadata_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		file := d.Val()

		// Create a MetadataSource entry and parse any block options
		src := &MetadataSource{File: file}

		// Check if there's a nested block with options
		nesting := d.Nesting()
		for d.NextBlock(nesting) {
			switch d.Val() {
			case "idp_filter":
				if !d.NextArg() {
					return true, d.ArgErr()
				}
				src.IdPFilter = d.Val()

			case "refresh_interval":
				if !d.NextArg() {
					return true, d.ArgErr()
				}
				interval, err := parseDuration(d.Val())
				if err != nil {
					return true, d.Errf("refresh_interval: %v", err)
				}
				src.RefreshInterval = interval

			default:
				return true, d.Errf("unrecognized metadata_file block option: %s", d.Val())
			}
		}

		// Always add to MetadataSources for multi-source support
		src.SetDefaults()
		cfg.MetadataSources = append(cfg.MetadataSources, *src)

	case "cert_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.CertFile = d.Val()

	case "key_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.KeyFile = d.Val()

	case "acs_url":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.AcsURL = d.Val()

	case "metadata_refresh_interval":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.MetadataRefreshInterval = d.Val()

	case "background_refresh":
		cfg.BackgroundRefresh = true

	case "session_cookie_name":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.SessionCookieName = d.Val()

	case "session_duration":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.SessionDuration = d.Val()

	case "remember_idp_cookie_name":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.RememberIdPCookieName = d.Val()

	case "remember_idp_duration":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.RememberIdPDuration = d.Val()

	case "templates_dir":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.TemplatesDir = d.Val()

	case "login_redirect":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.LoginRedirect = d.Val()

	case "idp_filter":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.IdPFilter = d.Val()

	case "registration_authority_filter":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.RegistrationAuthorityFilter = d.Val()

	case "entity_category_filter":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.EntityCategoryFilter = d.Val()

	case "assurance_certification_filter":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.AssuranceCertificationFilter = d.Val()

	case "discovery_template":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.DiscoveryTemplate = d.Val()

	case "service_name":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.ServiceName = d.Val()

	case "pinned_idps":
		cfg.PinnedIdPs = d.RemainingArgs()
		if len(cfg.PinnedIdPs) == 0 {
			return true, d.ArgErr()
		}

	case "alt_login":
		args := d.RemainingArgs()
		if len(args) < 2 {
			return true, d.ArgErr()
		}
		cfg.AltLogins = append(cfg.AltLogins, AltLoginConfig{
			URL:   args[0],
			Label: args[1],
		})

	case "cors_origins":
		cfg.CORSAllowedOrigins = d.RemainingArgs()
		if len(cfg.CORSAllowedOrigins) == 0 {
			return true, d.ArgErr()
		}

	case "cors_allow_credentials":
		cfg.CORSAllowCredentials = true

	case "default_language":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.DefaultLanguage = d.Val()

	case "verify_metadata_signature":
		cfg.VerifyMetadataSignature = true

	case "metadata_signing_cert":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.MetadataSigningCert = d.Val()

	case "sign_metadata":
		cfg.SignMetadata = true

	case "metrics":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		switch d.Val() {
		case "enabled", "on":
			cfg.MetricsEnabled = true
		case "disabled", "off":
			cfg.MetricsEnabled = false
		default:
			return true, d.Errf("metrics must be 'enabled' or 'off', got %q", d.Val())
		}

	case "attribute_headers":
		// Parse the attribute_headers block
		// Header validation is deferred to Config.Validate()
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			args := []string{d.Val()}
			args = append(args, d.RemainingArgs()...)

			if len(args) < 2 || len(args) > 3 {
				return true, d.Errf("attribute_headers: expected 2-3 arguments (saml_attribute header_name [separator]), got %d", len(args))
			}

			mapping := AttributeMapping{
				SAMLAttribute: args[0],
				HeaderName:    args[1],
			}
			if len(args) == 3 {
				mapping.Separator = args[2]
			}

			cfg.AttributeHeaders = append(cfg.AttributeHeaders, mapping)
		}

	case "strip_attribute_headers":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		val := strings.ToLower(d.Val())
		switch val {
		case "on", "true", "enabled":
			cfg.StripAttributeHeaders = boolPtr(true)
		case "off", "false", "disabled":
			cfg.StripAttributeHeaders = boolPtr(false)
		default:
			return true, d.Errf("strip_attribute_headers must be on/off, got %q", d.Val())
		}

	case "header_prefix":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.HeaderPrefix = d.Val()

	case "force_authn":
		cfg.ForceAuthn = true

	case "force_authn_paths":
		cfg.ForceAuthnPaths = d.RemainingArgs()
		if len(cfg.ForceAuthnPaths) == 0 {
			return true, d.Err("force_authn_paths requires at least one path pattern")
		}

	case "authn_context":
		args := d.RemainingArgs()
		if len(args) == 0 {
			return true, d.ArgErr()
		}
		cfg.AuthnContext = append(cfg.AuthnContext, args...)

	case "authn_context_comparison":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.AuthnContextComparison = d.Val()

	case "entitlements_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.EntitlementsFile = d.Val()

	case "entitlements_refresh_interval":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.EntitlementsRefreshInterval = d.Val()

	case "entitlement_headers":
		// Parse the entitlement_headers block
		// Header validation is deferred to Config.Validate()
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			args := []string{d.Val()}
			args = append(args, d.RemainingArgs()...)

			if len(args) < 2 || len(args) > 3 {
				return true, d.Errf("entitlement_headers: expected 2-3 arguments (field header_name [separator]), got %d", len(args))
			}

			mapping := EntitlementHeaderMapping{
				Field:      args[0],
				HeaderName: args[1],
			}
			if len(args) == 3 {
				mapping.Separator = args[2]
			}

			cfg.EntitlementHeaders = append(cfg.EntitlementHeaders, mapping)
		}

	case "require_entitlement":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.RequireEntitlement = d.Val()

	case "entitlement_deny_redirect":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		cfg.EntitlementDenyRedirect = d.Val()

	default:
		return false, nil // Not a Config directive
	}
	return true, nil
}

// parseDuration parses a duration string (e.g., "1h", "30m").
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
