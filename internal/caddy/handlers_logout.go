package caddy

import (
	"net/http"
	"net/url"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/logout"
)

func sloURL(r *http.Request) *url.URL {
	return &url.URL{
		Scheme: httputil.ResolveScheme(r),
		Host:   r.Host,
		Path:   "/saml/slo",
	}
}

func (s *SAMLDisco) buildLogoutHandler(cfg *SPConfig) *logout.LogoutHandler {
	return &logout.LogoutHandler{
		MetadataStore: cfg.metadataStore,
		SAMLService:   cfg.samlService,
		Logger:        s.getLogger(),
		ClearSessionCookies: func(w http.ResponseWriter, r *http.Request) {
			s.clearSessionCookies(w, r, cfg)
		},
		RenderAppError: s.renderAppError,
		ValidateRelayState: httputil.ValidateRelayState,
		ResolveSLOURL:      sloURL,
		GetSession:         GetSession,
	}
}

func (s *SAMLDisco) handleLogoutInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.buildLogoutHandler(cfg).Logout(w, r)
}

func (s *SAMLDisco) handleSLOInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.buildLogoutHandler(cfg).SLO(w, r)
}
