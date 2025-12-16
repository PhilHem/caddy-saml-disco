package caddysamldisco

import "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"

// Re-export template types and functions from adapter
type TemplateRenderer = caddy.TemplateRenderer
type DiscoData = caddy.DiscoData
type AltLoginOption = caddy.AltLoginOption
type ErrorData = caddy.ErrorData

var (
	NewTemplateRenderer            = caddy.NewTemplateRenderer
	NewTemplateRendererWithTemplate = caddy.NewTemplateRendererWithTemplate
	NewTemplateRendererWithDir     = caddy.NewTemplateRendererWithDir
)
