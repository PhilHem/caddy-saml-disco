package caddysamldisco

import "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"

// Re-export Config and related types from adapter
type Config = caddy.Config
type AltLoginConfig = caddy.AltLoginConfig
type AttributeMapping = caddy.AttributeMapping

var (
	IsValidHeaderName      = caddy.IsValidHeaderName
	ApplyHeaderPrefix      = caddy.ApplyHeaderPrefix
	MapAttributesToHeaders = caddy.MapAttributesToHeaders
)

// Note: sanitizeHeaderValue is not exported from caddy package (internal function)
// Tests that need it should import caddy package directly or use a test helper

const (
	MaxHeaderValueLength = caddy.MaxHeaderValueLength
)
