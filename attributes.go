package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Re-export ResolveAttributeName from domain
var ResolveAttributeName = domain.ResolveAttributeName

// Other re-exports are in plugin.go to avoid duplication
