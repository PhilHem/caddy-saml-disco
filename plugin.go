// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Version information - set via ldflags at build time
// e.g., go build -ldflags "-X github.com/philiph/caddy-saml-disco.Version=v1.0.0"
var (
	Version   = "dev"
	GitCommit = ""
	BuildTime = ""
)

// Re-export Caddy adapter types (other re-exports are in their respective files)
type SAMLDisco = caddyadapter.SAMLDisco
type HealthResponse = caddyadapter.HealthResponse

var (
	MapAttributesToHeadersWithPrefix = domain.MapAttributesToHeadersWithPrefix
	ValidateDenyRedirect             = caddyadapter.ValidateDenyRedirect
	ValidateRelayState               = caddyadapter.ValidateRelayState
	ParseAcceptLanguage              = caddyadapter.ParseAcceptLanguage
	ParseDuration                    = caddyadapter.ParseDuration
	MatchesForceAuthnPath            = caddyadapter.MatchesForceAuthnPath
	SetVersionGetters                = caddyadapter.SetVersionGetters
)

func init() {
	// Inject version info into adapter to avoid import cycles
	caddyadapter.SetVersionGetters(
		func() string { return Version },
		func() string { return GitCommit },
		func() string { return BuildTime },
	)

	caddy.RegisterModule(caddyadapter.SAMLDisco{})
	httpcaddyfile.RegisterHandlerDirective("saml_disco", caddyadapter.ParseCaddyfile)
}
