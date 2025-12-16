package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Re-export SAMLService and related types from adapter
type SAMLService = caddy.SAMLService
type AuthResult = caddy.AuthResult
type AuthnOptions = domain.AuthnOptions

var (
	NewSAMLService      = caddy.NewSAMLService
	NewSAMLServiceWithStore = caddy.NewSAMLServiceWithStore
)
