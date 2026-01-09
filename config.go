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
	IsValidHeaderName       = domain.IsValidHeaderName
	ApplyHeaderPrefix       = domain.ApplyHeaderPrefix
	MapAttributesToHeaders  = domain.MapAttributesToHeaders
	SanitizeHeaderValue     = domain.SanitizeHeaderValue
	NewCaddyAttributeMapper = caddy.NewCaddyAttributeMapper
)

const (
	MaxHeaderValueLength = domain.MaxHeaderValueLength
)
