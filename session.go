package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
)

// Re-export Session from domain package
type Session = domain.Session

// Re-export SessionStore interface from ports
type SessionStore = ports.SessionStore

// Re-export ErrSessionNotFound from ports
var ErrSessionNotFound = ports.ErrSessionNotFound

// Re-export session adapter
type CookieSessionStore = session.CookieSessionStore

var (
	NewCookieSessionStore = session.NewCookieSessionStore
	LoadPrivateKey        = session.LoadPrivateKey
	LoadCertificate       = session.LoadCertificate
	GetSession            = caddy.GetSession
)
