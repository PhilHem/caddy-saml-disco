package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Re-export Config and related types from adapter
type Config = caddy.Config
type AltLoginConfig = caddy.AltLoginConfig
type AttributeMapping = caddy.AttributeMapping

// Re-export port types for testing through interfaces
type PortAttributeMapping = ports.AttributeMapping
type AttributeMapper = ports.AttributeMapper

var (
	IsValidHeaderName      = domain.IsValidHeaderName
	ApplyHeaderPrefix      = caddy.ApplyHeaderPrefix
	MapAttributesToHeaders = caddy.MapAttributesToHeaders
	NewCaddyAttributeMapper = caddy.NewCaddyAttributeMapper
)

// Note: sanitizeHeaderValue is not exported from caddy package (internal function)
// Tests that need it should import caddy package directly or use a test helper

const (
	MaxHeaderValueLength = caddy.MaxHeaderValueLength
)
