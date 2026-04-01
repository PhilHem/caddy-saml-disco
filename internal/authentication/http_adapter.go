package authentication

import (
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// Deps holds the dependencies needed to construct an HTTPAdapter.
// The caddy layer builds this struct and passes it to NewHTTPAdapter.
type Deps struct {
	// Core services
	SAMLService      *samlsvc.SAMLService
	MetadataStore    ports.MetadataStore
	SessionStore     ports.SessionStore
	EntitlementStore ports.EntitlementStore
	MetricsRecorder  ports.MetricsRecorder
	Logger           *zap.Logger

	// SP config fields needed for auth
	EntityID           string
	ACSURL             string
	SessionDuration    time.Duration
	RequireEntitlement string

	// Cookie writer — called on successful authentication to write the session cookie.
	// The adapter calls this before redirecting the user.
	SetSessionCookie func(w http.ResponseWriter, r *http.Request, token string)

	// DenyRedirect is the URL to redirect denied users to.
	// When empty the adapter returns a 403 via RenderAppError instead.
	DenyRedirect string

	// RenderAppError writes an error response appropriate to the request.
	// API paths (/saml/api/*) receive JSON; all others receive HTML.
	RenderAppError func(w http.ResponseWriter, r *http.Request, err *domain.AppError)
}

// HTTPAdapter wraps AuthHandler and wires the caddy-layer callbacks so that
// internal/caddy/ only needs to construct Deps and call ServeMetadata / ServeACS.
type HTTPAdapter struct {
	handler *AuthHandler
}

// NewHTTPAdapter constructs an HTTPAdapter from the given Deps.
func NewHTTPAdapter(deps Deps) *HTTPAdapter {
	h := &AuthHandler{
		SAMLService:      deps.SAMLService,
		MetadataStore:    deps.MetadataStore,
		SessionStore:     deps.SessionStore,
		EntitlementStore: deps.EntitlementStore,
		MetricsRecorder:  deps.MetricsRecorder,
		Logger:           deps.Logger,
		Config: AuthConfig{
			EntityID:           deps.EntityID,
			ACSURL:             deps.ACSURL,
			SessionDuration:    deps.SessionDuration,
			RequireEntitlement: deps.RequireEntitlement,
		},
	}

	h.OnAuthenticated = func(w http.ResponseWriter, r *http.Request, token string, _ *domain.Session) {
		deps.SetSessionCookie(w, r, token)
		relayState := httputil.ValidateRelayState(r.FormValue("RelayState"))
		http.Redirect(w, r, relayState, http.StatusFound)
	}

	h.OnDenied = func(w http.ResponseWriter, r *http.Request, subject string) {
		if deps.DenyRedirect != "" {
			http.Redirect(w, r, deps.DenyRedirect, http.StatusFound)
			return
		}
		if deps.RenderAppError != nil {
			deps.RenderAppError(w, r, &domain.AppError{
				Code:    domain.ErrCodeBadRequest,
				Message: "Access denied by entitlements policy",
				Cause:   domain.ErrAccessDenied,
			})
			return
		}
		http.Error(w, "Access denied", http.StatusForbidden)
	}

	h.OnError = func(w http.ResponseWriter, r *http.Request, err *domain.AppError) {
		if deps.RenderAppError != nil {
			deps.RenderAppError(w, r, err)
			return
		}
		http.Error(w, err.Message, http.StatusInternalServerError)
	}

	return &HTTPAdapter{handler: h}
}

// ServeMetadata writes the SP metadata XML.
func (a *HTTPAdapter) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	a.handler.Metadata(w, r)
}

// ServeACS processes a SAML POST-binding ACS response.
func (a *HTTPAdapter) ServeACS(w http.ResponseWriter, r *http.Request) error {
	return a.handler.ACS(w, r)
}
