package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/logo"
)

// Re-export LogoStore interface and CachedLogo from ports
type LogoStore = ports.LogoStore
type CachedLogo = ports.CachedLogo

// Re-export logo adapters
type InMemoryLogoStore = logo.InMemoryLogoStore
type CachingLogoStore = logo.CachingLogoStore

var (
	NewInMemoryLogoStore = logo.NewInMemoryLogoStore
	NewCachingLogoStore  = logo.NewCachingLogoStore
	WithLogoMaxSize      = logo.WithLogoMaxSize
)

// Re-export logo errors
var (
	ErrLogoNotFound      = logo.ErrLogoNotFound
	ErrLogoFetchFailed   = logo.ErrLogoFetchFailed
	ErrInvalidContentType = logo.ErrInvalidContentType
)
