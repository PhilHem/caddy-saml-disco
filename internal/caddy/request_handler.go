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

func (s *SAMLDisco) serveSPRequest(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, spConfig *SPConfig) error {
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		httputil.ApplyCORSHeaders(w, r, s.CORSAllowedOrigins, s.CORSAllowCredentials)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
	}
	if strings.HasPrefix(r.URL.Path, "/saml/api/logo/") && r.Method == http.MethodGet {
		return s.handleLogoEndpointInternal(w, r, spConfig)
	}
	switch r.URL.Path {
	case "/saml/metadata":
		if r.Method == http.MethodGet {
			return s.handleMetadataInternal(w, r, spConfig)
		}
	case "/saml/acs":
		if r.Method == http.MethodPost {
			return s.handleACSInternal(w, r, spConfig)
		}
	case "/saml/logout":
		if r.Method == http.MethodGet {
			return s.handleLogoutInternal(w, r, spConfig)
		}
	case "/saml/slo":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			return s.handleSLOInternal(w, r, spConfig)
		}
	case "/saml/api/idps":
		if r.Method == http.MethodGet {
			return s.handleListIdPsInternal(w, r, spConfig)
		}
	case "/saml/api/select":
		if r.Method == http.MethodPost {
			return s.handleSelectIdPInternal(w, r, spConfig)
		}
	case "/saml/api/session":
		if r.Method == http.MethodGet {
			return s.handleSessionInfoInternal(w, r, spConfig)
		}
	case "/saml/api/health":
		if r.Method == http.MethodGet {
			return s.handleHealthInternal(w, r, spConfig)
		}
	case "/saml/health":
		if r.Method == http.MethodGet {
			return s.handleSimpleHealthInternal(w, r, spConfig)
		}
	case "/saml/disco":
		if r.Method == http.MethodGet {
			return s.handleDiscoveryUIInternal(w, r, spConfig)
		}
	}
	if spConfig.sessionStore != nil && !strings.HasPrefix(r.URL.Path, "/saml/") {
		cookie, err := r.Cookie(spConfig.Config.SessionCookieName)
		if err != nil || cookie.Value == "" {
			s.redirectToIdPInternal(w, r, spConfig)
			return nil
		}
		session, err := spConfig.sessionStore.Get(cookie.Value)
		if err != nil {
			s.getMetricsRecorder().RecordSessionValidation(false)
			s.redirectToIdPInternal(w, r, spConfig)
			return nil
		}
		s.getMetricsRecorder().RecordSessionValidation(true)
		ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
		r = r.WithContext(ctx)
		if len(spConfig.AttributeHeaders) > 0 || len(spConfig.EntitlementHeaders) > 0 {
			s.applyAttributeHeaders(r, session, spConfig)
		}
	}
	return next.ServeHTTP(w, r)
}

func (s *SAMLDisco) getLogger() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	return zap.NewNop()
}
