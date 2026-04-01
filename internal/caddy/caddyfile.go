package caddy

import (
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func ParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s SAMLDisco
	err := s.UnmarshalCaddyfile(h.Dispenser)
	return &s, err
}

func (s *SAMLDisco) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		switch d.Val() {
		case "sp":
			if !d.NextArg() {
				return d.ArgErr()
			}
			hostname := d.Val()
			spCfg := &SPConfig{SPConfig: config.SPConfig{Hostname: hostname}}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				if err := s.parseSPConfigField(d, spCfg, nesting); err != nil {
					return err
				}
			}
			s.SPConfigs = append(s.SPConfigs, spCfg)

		default:
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

func parseStringField(d *caddyfile.Dispenser, target *string) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	*target = d.Val()
	return nil
}

func parseMetadataSourceBlock(d *caddyfile.Dispenser, src *MetadataSource) error {
	nesting := d.Nesting()
	for d.NextBlock(nesting) {
		switch d.Val() {
		case "idp_filter":
			if err := parseStringField(d, &src.IdPFilter); err != nil {
				return err
			}
		case "refresh_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			interval, err := time.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("refresh_interval: %v", err)
			}
			src.RefreshInterval = interval
		default:
			return d.Errf("unrecognized metadata source block option: %s", d.Val())
		}
	}
	return nil
}

func parseConfigDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	if handled, err := parseAuthDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseMetadataDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseSessionDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseHeaderDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseEntitlementDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseUIDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	if handled, err := parseMetricsDirective(d, cfg); handled || err != nil {
		return handled, err
	}
	return false, nil
}

// parseAuthDirective handles SP identity and SAML authentication directives:
// entity_id, cert_file, key_file, acs_url, request_ttl, force_authn,
// force_authn_paths, authn_context, authn_context_comparison, sign_metadata, bypass_idp.
func parseAuthDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
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
	case "cert_file":
		return true, parseStringField(d, &cfg.CertFile)
	case "key_file":
		return true, parseStringField(d, &cfg.KeyFile)
	case "acs_url":
		return true, parseStringField(d, &cfg.AcsURL)
	case "request_ttl":
		return true, parseStringField(d, &cfg.RequestTTL)
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
		return true, parseStringField(d, &cfg.AuthnContextComparison)
	case "sign_metadata":
		cfg.SignMetadata = true
	case "bypass_idp":
		args := d.RemainingArgs()
		if len(args) == 0 {
			return true, d.ArgErr()
		}
		cfg.BypassIdPs = append(cfg.BypassIdPs, args...)
	default:
		return false, nil
	}
	return true, nil
}

// parseMetadataDirective handles metadata source and filtering directives:
// metadata_url, metadata_file, metadata_sources, metadata_refresh_interval,
// background_refresh, verify_metadata_signature, metadata_signing_cert,
// idp_filter, registration_authority_filter, entity_category_filter,
// assurance_certification_filter.
func parseMetadataDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "metadata_url":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		src := &MetadataSource{URL: d.Val()}
		if err := parseMetadataSourceBlock(d, src); err != nil {
			return true, err
		}
		src.SetDefaults()
		cfg.MetadataSources = append(cfg.MetadataSources, *src)
	case "metadata_file":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		src := &MetadataSource{File: d.Val()}
		if err := parseMetadataSourceBlock(d, src); err != nil {
			return true, err
		}
		src.SetDefaults()
		cfg.MetadataSources = append(cfg.MetadataSources, *src)
	case "metadata_refresh_interval":
		return true, parseStringField(d, &cfg.MetadataRefreshInterval)
	case "background_refresh":
		cfg.BackgroundRefresh = true
	case "verify_metadata_signature":
		cfg.VerifyMetadataSignature = true
	case "metadata_signing_cert":
		return true, parseStringField(d, &cfg.MetadataSigningCert)
	case "idp_filter":
		return true, parseStringField(d, &cfg.IdPFilter)
	case "registration_authority_filter":
		return true, parseStringField(d, &cfg.RegistrationAuthorityFilter)
	case "entity_category_filter":
		return true, parseStringField(d, &cfg.EntityCategoryFilter)
	case "assurance_certification_filter":
		return true, parseStringField(d, &cfg.AssuranceCertificationFilter)
	default:
		return false, nil
	}
	return true, nil
}

// parseSessionDirective handles session and cookie directives:
// session_cookie_name, session_duration, cookie_secure,
// remember_idp_cookie_name, remember_idp_duration.
func parseSessionDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "session_cookie_name":
		return true, parseStringField(d, &cfg.SessionCookieName)
	case "session_duration":
		return true, parseStringField(d, &cfg.SessionDuration)
	case "cookie_secure":
		if !d.NextArg() {
			return true, d.ArgErr()
		}
		val := d.Val()
		switch val {
		case "auto", "always", "never":
			cfg.CookieSecure = val
		default:
			return true, d.Errf("cookie_secure must be \"auto\", \"always\", or \"never\", got %q", val)
		}
	case "remember_idp_cookie_name":
		return true, parseStringField(d, &cfg.RememberIdPCookieName)
	case "remember_idp_duration":
		return true, parseStringField(d, &cfg.RememberIdPDuration)
	default:
		return false, nil
	}
	return true, nil
}

// parseHeaderDirective handles attribute-to-header mapping directives:
// attribute_headers, strip_attribute_headers, header_prefix.
func parseHeaderDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "attribute_headers":
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			args := []string{d.Val()}
			args = append(args, d.RemainingArgs()...)
			if len(args) < 2 || len(args) > 3 {
				return true, d.Errf("attribute_headers: expected 2-3 arguments (saml_attribute header_name [separator]), got %d", len(args))
			}
			mapping := domain.AttributeMapping{SAMLAttribute: args[0], HeaderName: args[1]}
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
		return true, parseStringField(d, &cfg.HeaderPrefix)
	default:
		return false, nil
	}
	return true, nil
}

// parseEntitlementDirective handles file-based entitlement directives:
// entitlements_file, entitlements_refresh_interval, require_entitlement,
// entitlement_deny_redirect, entitlement_headers.
func parseEntitlementDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "entitlements_file":
		return true, parseStringField(d, &cfg.EntitlementsFile)
	case "entitlements_refresh_interval":
		return true, parseStringField(d, &cfg.EntitlementsRefreshInterval)
	case "require_entitlement":
		return true, parseStringField(d, &cfg.RequireEntitlement)
	case "entitlement_deny_redirect":
		return true, parseStringField(d, &cfg.EntitlementDenyRedirect)
	case "entitlement_headers":
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			args := []string{d.Val()}
			args = append(args, d.RemainingArgs()...)
			if len(args) < 2 || len(args) > 3 {
				return true, d.Errf("entitlement_headers: expected 2-3 arguments (field header_name [separator]), got %d", len(args))
			}
			mapping := httputil.EntitlementHeaderMapping{Field: args[0], HeaderName: args[1]}
			if len(args) == 3 {
				mapping.Separator = args[2]
			}
			cfg.EntitlementHeaders = append(cfg.EntitlementHeaders, mapping)
		}
	default:
		return false, nil
	}
	return true, nil
}

// parseUIDirective handles discovery UI and frontend directives:
// discovery_template, templates_dir, default_language, service_name,
// pinned_idps, guest_access, alt_login, cors_origins, cors_allow_credentials,
// login_redirect.
func parseUIDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
	case "discovery_template":
		return true, parseStringField(d, &cfg.DiscoveryTemplate)
	case "templates_dir":
		return true, parseStringField(d, &cfg.TemplatesDir)
	case "default_language":
		return true, parseStringField(d, &cfg.DefaultLanguage)
	case "service_name":
		return true, parseStringField(d, &cfg.ServiceName)
	case "pinned_idps":
		cfg.PinnedIdPs = d.RemainingArgs()
		if len(cfg.PinnedIdPs) == 0 {
			return true, d.ArgErr()
		}
	case "guest_access":
		return true, parseStringField(d, &cfg.GuestAccessLabel)
	case "alt_login":
		args := d.RemainingArgs()
		if len(args) < 2 {
			return true, d.ArgErr()
		}
		cfg.AltLogins = append(cfg.AltLogins, AltLoginConfig{URL: args[0], Label: args[1]})
	case "cors_origins":
		cfg.CORSAllowedOrigins = d.RemainingArgs()
		if len(cfg.CORSAllowedOrigins) == 0 {
			return true, d.ArgErr()
		}
	case "cors_allow_credentials":
		cfg.CORSAllowCredentials = true
	case "login_redirect":
		return true, parseStringField(d, &cfg.LoginRedirect)
	default:
		return false, nil
	}
	return true, nil
}

// parseMetricsDirective handles observability directives: metrics.
func parseMetricsDirective(d *caddyfile.Dispenser, cfg *Config) (bool, error) {
	switch d.Val() {
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
	default:
		return false, nil
	}
	return true, nil
}
