package discovery

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// AdapterDeps holds the resolved configuration and services needed to build a
// DiscoveryHandler. The caddy layer constructs this struct — it is responsible
// for parsing string durations and converting any caddy-specific types before
// handing them off here.
type AdapterDeps struct {
	// Core services
	MetadataStore ports.MetadataStore
	SessionStore  ports.SessionStore
	SAMLService   AuthStarter // nil-safe; wrap *saml.SAMLService before passing
	Renderer      *TemplateRenderer
	Logger        *zap.Logger

	// Resolved configuration fields (caddy layer has already parsed durations and
	// converted AltLogins from caddy's AltLoginConfig to discovery.AltLoginConfig).
	DefaultLanguage       string
	PinnedIdPs            []string
	BypassIdPs            []string
	GuestAccessLabel      string
	GuestPasscode         string
	GuestPasscodes        map[string]string
	AltLogins             []AltLoginConfig
	ServiceName           string
	ForceAuthn            bool
	ForceAuthnPaths       []string
	RememberIdPCookieName string
	RememberIdPDuration   time.Duration // pre-parsed; zero means no remember-IdP cookie
	SessionCookieName     string
	SessionCookieDomain   string
	SessionDuration       time.Duration
	AcsURL                string
	LoginRedirect         string
	CookieSecure          string
}

// HTTPAdapter wraps DiscoveryHandler and exposes its HTTP methods directly,
// so that internal/caddy/ delegates without knowing DiscoveryHandler internals.
type HTTPAdapter struct {
	handler *DiscoveryHandler
}

// NewHTTPAdapter constructs an HTTPAdapter from the given AdapterDeps.
// The SAMLService field is safe to pass as a nil *saml.SAMLService — this
// constructor handles the nil-interface-wrapping hazard automatically.
func NewHTTPAdapter(deps AdapterDeps) *HTTPAdapter {
	return &HTTPAdapter{
		handler: &DiscoveryHandler{
			MetadataStore: deps.MetadataStore,
			SessionStore:  deps.SessionStore,
			SAMLService:   deps.SAMLService,
			Renderer:      deps.Renderer,
			Logger:        deps.Logger,
			Config: Config{
				DefaultLanguage:       deps.DefaultLanguage,
				PinnedIdPs:            deps.PinnedIdPs,
				BypassIdPs:            deps.BypassIdPs,
				GuestAccessLabel:      deps.GuestAccessLabel,
				GuestPasscode:         deps.GuestPasscode,
				GuestPasscodes:        deps.GuestPasscodes,
				AltLogins:             deps.AltLogins,
				ServiceName:           deps.ServiceName,
				ForceAuthn:            deps.ForceAuthn,
				ForceAuthnPaths:       deps.ForceAuthnPaths,
				RememberIdPCookieName: deps.RememberIdPCookieName,
				RememberIdPDuration:   deps.RememberIdPDuration,
				SessionCookieName:     deps.SessionCookieName,
				SessionCookieDomain:   deps.SessionCookieDomain,
				SessionDuration:       deps.SessionDuration,
				AcsURL:                deps.AcsURL,
				LoginRedirect:         deps.LoginRedirect,
				CookieSecure:          deps.CookieSecure,
			},
		},
	}
}

// HandleListIdPs handles GET /saml/api/idps.
func (a *HTTPAdapter) HandleListIdPs(w http.ResponseWriter, r *http.Request) error {
	return a.handler.HandleListIdPs(w, r)
}

// HandleSelectIdP handles POST /saml/api/select.
func (a *HTTPAdapter) HandleSelectIdP(w http.ResponseWriter, r *http.Request) error {
	return a.handler.HandleSelectIdP(w, r)
}

// HandleDiscoveryUI handles GET /saml/disco.
func (a *HTTPAdapter) HandleDiscoveryUI(w http.ResponseWriter, r *http.Request) error {
	return a.handler.HandleDiscoveryUI(w, r)
}

// HandleRedirectToIdP handles unauthenticated requests to protected routes.
func (a *HTTPAdapter) HandleRedirectToIdP(w http.ResponseWriter, r *http.Request) {
	a.handler.HandleRedirectToIdP(w, r)
}
