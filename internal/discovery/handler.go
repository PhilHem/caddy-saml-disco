// Package discovery implements IdP discovery: the UI, JSON API, and IdP selection
// logic that lets users choose which Identity Provider to authenticate with.
package discovery

import (
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// GuestEntityID is a sentinel entity ID used for guest access entries.
// It never appears in real federation metadata.
const GuestEntityID = "urn:caddy-saml-disco:guest"

// AuthStarter initiates a SAML authentication flow.
// Satisfied by *saml.SAMLService.
type AuthStarter interface {
	StartAuthWithOptions(idp *domain.IdPInfo, acsURL *url.URL, relayState string, opts *domain.AuthnOptions) (*url.URL, error)
}

// AltLoginConfig is an alternative login method (non-SAML).
type AltLoginConfig struct {
	URL   string
	Label string
}

// Config holds the discovery-specific configuration fields needed by DiscoveryHandler.
type Config struct {
	// DefaultLanguage is the fallback language for display names.
	DefaultLanguage string

	// PinnedIdPs is the list of IdP entity IDs to show prominently.
	PinnedIdPs []string

	// BypassIdPs is the list of IdP entity IDs that skip SAML and create a guest session.
	BypassIdPs []string

	// GuestAccessLabel is the display name for a virtual guest access entry.
	// When non-empty a guest entry appears at the bottom of the discovery page.
	GuestAccessLabel string

	// GuestPasscode gates the no-authentication paths (guest_access and
	// bypass_idp). When non-empty, a guest or bypass session is only created if
	// the caller supplies a matching passcode. Empty means ungated.
	GuestPasscode string

	// AltLogins is a list of alternative login methods.
	AltLogins []AltLoginConfig

	// ServiceName is displayed in the discovery UI header.
	ServiceName string

	// ForceAuthn requires fresh authentication for all protected routes.
	ForceAuthn bool

	// ForceAuthnPaths is a list of glob patterns for routes requiring fresh authentication.
	ForceAuthnPaths []string

	// RememberIdPCookieName is the name of the cookie that stores the last-used IdP.
	RememberIdPCookieName string

	// RememberIdPDuration is the parsed duration for the remember-IdP cookie.
	// Zero means no remember-IdP cookie.
	RememberIdPDuration time.Duration

	// SessionCookieName is the name of the session cookie.
	SessionCookieName string

	// SessionCookieDomain is the domain attribute for the session cookie.
	// Empty means no domain (uses request host).
	SessionCookieDomain string

	// SessionDuration is how long sessions last.
	SessionDuration time.Duration

	// AcsURL overrides the computed ACS URL. Empty means compute from request.
	AcsURL string

	// LoginRedirect is the URL to redirect to for login instead of the built-in UI.
	LoginRedirect string

	// CookieSecure controls when the Secure flag is set on cookies.
	// Values: "auto" (default), "always", "never". See httputil.resolveSecure.
	CookieSecure string
}

// DiscoveryHandler handles all IdP discovery requests: the discovery UI, the JSON API
// (/saml/api/idps, /saml/api/select), and the redirect-to-IdP logic.
type DiscoveryHandler struct {
	MetadataStore ports.MetadataStore
	SessionStore  ports.SessionStore
	SAMLService   AuthStarter
	Renderer      *TemplateRenderer
	Logger        *zap.Logger
	Config        Config
}

// getLogger returns the logger, or a no-op logger if not set.
func (h *DiscoveryHandler) getLogger() *zap.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return zap.NewNop()
}

// cookieConfig implements httputil.CookieConfig for this handler's config.
type cookieConfig struct {
	cfg Config
}

func (c cookieConfig) SessionCookieName() string          { return c.cfg.SessionCookieName }
func (c cookieConfig) SessionCookieDomain() string        { return c.cfg.SessionCookieDomain }
func (c cookieConfig) SessionDuration() time.Duration     { return c.cfg.SessionDuration }
func (c cookieConfig) RememberIdPCookieName() string      { return c.cfg.RememberIdPCookieName }
func (c cookieConfig) RememberIdPDuration() time.Duration { return c.cfg.RememberIdPDuration }
func (c cookieConfig) CookieSecureMode() string           { return c.cfg.CookieSecure }

var _ httputil.CookieConfig = cookieConfig{}
