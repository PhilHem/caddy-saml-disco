// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
package caddysamldisco

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	caddyadapter "github.com/philiph/caddy-saml-disco/internal/caddy"
)

// Version information - set via ldflags at build time
// e.g., go build -ldflags "-X github.com/philiph/caddy-saml-disco.Version=v1.0.0"
var (
	Version   = "dev"
	GitCommit = ""
	BuildTime = ""
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
