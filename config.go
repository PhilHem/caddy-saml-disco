package caddysamldisco

import "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"

// Re-export Config and related types from adapter
type Config = caddy.Config
type AltLoginConfig = caddy.AltLoginConfig
type AttributeMapping = caddy.AttributeMapping

var (
	IsValidHeaderName = caddy.IsValidHeaderName
	ApplyHeaderPrefix = caddy.ApplyHeaderPrefix
)
