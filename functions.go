// Package caddysamldisco provides a Caddy v2 plugin for SAML Service Provider
// authentication with Discovery Service support.
//
// This file re-exports functions and variables from internal packages
// that external consumers need.
package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Domain Errors

var (
	// ErrIdPNotFound is returned when an IdP is not found.
	ErrIdPNotFound = domain.ErrIdPNotFound
)

// Session Adapter Functions

var (
	// NewCookieSessionStore creates a cookie-based session store.
	NewCookieSessionStore = session.NewCookieSessionStore
	// LoadPrivateKey loads a private key from a file.
	LoadPrivateKey = session.LoadPrivateKey
	// LoadCertificate loads a certificate from a file.
	LoadCertificate = session.LoadCertificate
)

// Metadata Adapter Functions

var (
	// NewInMemoryMetadataStore creates an in-memory metadata store.
	NewInMemoryMetadataStore = metadata.NewInMemoryMetadataStore
	// NewFileMetadataStore creates a file-based metadata store.
	NewFileMetadataStore = metadata.NewFileMetadataStore
)

// Logo Adapter Functions

var (
	// NewCachingLogoStore creates a caching logo store.
	NewCachingLogoStore = logo.NewCachingLogoStore
)

// Caddy Adapter Functions

var (
	// NewSAMLService creates a new SAML service.
	NewSAMLService = caddy.NewSAMLService
	// NewTemplateRenderer creates a new template renderer.
	NewTemplateRenderer = caddy.NewTemplateRenderer
	// NewTemplateRendererWithDir creates a renderer with a template directory.
	NewTemplateRendererWithDir = caddy.NewTemplateRendererWithDir
)
