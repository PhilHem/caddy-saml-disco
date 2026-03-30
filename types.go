// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
//
// This file re-exports types from internal packages that external consumers need.
package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/caddy"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// Domain Types

// Session represents an authenticated user session.
type Session = domain.Session

// IdPInfo contains identity provider information.
type IdPInfo = domain.IdPInfo

// MetadataHealth represents the health status of metadata.
type MetadataHealth = domain.MetadataHealth

// AuthnOptions contains SAML authentication request options.
type AuthnOptions = domain.AuthnOptions

// Port Interfaces

// MetadataStore provides access to IdP metadata.
type MetadataStore = ports.MetadataStore

// SessionStore manages user sessions.
type SessionStore = ports.SessionStore

// Adapter Types

// SAMLDisco is the main Caddy module for SAML authentication.
type SAMLDisco = caddy.SAMLDisco

// Config contains SAML configuration for Caddy.
type Config = caddy.Config

// AttributeMapping maps SAML attributes to HTTP headers.
type AttributeMapping = caddy.AttributeMapping

// SAMLService handles SAML authentication flows.
type SAMLService = caddy.SAMLService

// TemplateRenderer renders HTML templates.
type TemplateRenderer = caddy.TemplateRenderer

// FileMetadataStore loads metadata from a file.
type FileMetadataStore = metadata.FileMetadataStore
