package caddy

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func (s *SAMLDisco) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if s.registry == nil {
		s.defaultSPConfig()
	}
	spConfig := s.registry.GetByHostname(r.Host)
	if spConfig == nil {
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("no SP config for hostname %q", r.Host))
	}
	return s.serveSPRequest(w, r, next, spConfig)
}

// spHandler serves one SAML endpoint for a resolved SP config.
type spHandler func(*SAMLDisco, http.ResponseWriter, *http.Request, *SPConfig) error

// samlRoutes maps an exact request path to the handler for each method it
// accepts. A path that is present but called with an unlisted method falls
// through to the downstream passthrough, matching plain reverse-proxy behaviour.
var samlRoutes = map[string]map[string]spHandler{
	"/saml/metadata":    {http.MethodGet: (*SAMLDisco).handleMetadataInternal},
	"/saml/acs":         {http.MethodPost: (*SAMLDisco).handleACSInternal},
	"/saml/logout":      {http.MethodGet: (*SAMLDisco).handleLogoutInternal},
	"/saml/slo":         {http.MethodGet: (*SAMLDisco).handleSLOInternal, http.MethodPost: (*SAMLDisco).handleSLOInternal},
	"/saml/api/idps":    {http.MethodGet: (*SAMLDisco).handleListIdPsInternal},
	"/saml/api/select":  {http.MethodPost: (*SAMLDisco).handleSelectIdPInternal},
	"/saml/api/session": {http.MethodGet: (*SAMLDisco).handleSessionInfoInternal},
	"/saml/api/health":  {http.MethodGet: (*SAMLDisco).handleHealthInternal},
	"/saml/health":      {http.MethodGet: (*SAMLDisco).handleSimpleHealthInternal},
	"/saml/disco":       {http.MethodGet: (*SAMLDisco).handleDiscoveryUIInternal},
}

func (s *SAMLDisco) serveSPRequest(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, spConfig *SPConfig) error {
	if s.answerCORSPreflight(w, r) {
		return nil
	}
	if strings.HasPrefix(r.URL.Path, "/saml/api/logo/") && r.Method == http.MethodGet {
		return s.handleLogoEndpointInternal(w, r, spConfig)
	}
	if handler := routeHandler(r.URL.Path, r.Method); handler != nil {
		return handler(s, w, r, spConfig)
	}
	return s.serveDownstream(w, r, next, spConfig)
}

// answerCORSPreflight applies CORS headers to /saml/api/ requests and reports
// whether the request was an OPTIONS preflight that has been fully answered.
func (s *SAMLDisco) answerCORSPreflight(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/saml/api/") {
		return false
	}
	httputil.ApplyCORSHeaders(w, r, s.CORSAllowedOrigins, s.CORSAllowCredentials)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// routeHandler returns the handler registered for an exact path and method, or
// nil when nothing matches.
func routeHandler(path, method string) spHandler {
	return samlRoutes[path][method]
}

// serveDownstream applies the SAML session to a non-SAML request and forwards it
// to the next handler. An unauthenticated request is redirected to the IdP.
func (s *SAMLDisco) serveDownstream(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, spConfig *SPConfig) error {
	if spConfig.sessionStore == nil || strings.HasPrefix(r.URL.Path, "/saml/") {
		return next.ServeHTTP(w, r)
	}
	cookie, err := r.Cookie(spConfig.Config.SessionCookieName)
	if err != nil || cookie.Value == "" {
		if s.answerSessionExpiredJSON(w, r, spConfig) {
			return nil
		}
		s.redirectToIdPInternal(w, r, spConfig)
		return nil
	}
	session, err := spConfig.sessionStore.Get(cookie.Value)
	if err != nil {
		s.getMetricsRecorder().RecordSessionValidation(false)
		if s.answerSessionExpiredJSON(w, r, spConfig) {
			return nil
		}
		s.redirectToIdPInternal(w, r, spConfig)
		return nil
	}
	s.getMetricsRecorder().RecordSessionValidation(true)
	ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
	r = r.WithContext(ctx)
	if len(spConfig.AttributeHeaders) > 0 || len(spConfig.EntitlementHeaders) > 0 {
		s.applyAttributeHeaders(r, session, spConfig)
	}
	return next.ServeHTTP(w, r)
}

func (s *SAMLDisco) getLogger() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	return zap.NewNop()
}
