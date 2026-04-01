package caddy

import (
	"net/http"

	"github.com/philiph/caddy-saml-disco/internal/authentication"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func (s *SAMLDisco) handleMetadataInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	s.buildAuthAdapter(cfg).ServeMetadata(w, r)
	return nil
}

func (s *SAMLDisco) handleACSInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.buildAuthAdapter(cfg).ServeACS(w, r)
}

func (s *SAMLDisco) buildAuthAdapter(cfg *SPConfig) *authentication.HTTPAdapter {
	return authentication.NewHTTPAdapter(authentication.Deps{
		SAMLService:        cfg.samlService,
		MetadataStore:      cfg.metadataStore,
		SessionStore:       cfg.sessionStore,
		EntitlementStore:   cfg.entitlementStore,
		MetricsRecorder:    s.getMetricsRecorder(),
		Logger:             s.getLogger(),
		EntityID:           cfg.EntityID,
		ACSURL:             cfg.AcsURL,
		SessionDuration:    cfg.sessionDuration,
		RequireEntitlement: cfg.RequireEntitlement,
		SetSessionCookie: func(w http.ResponseWriter, r *http.Request, token string) {
			s.setSessionCookie(w, r, cfg, token)
		},
		DenyRedirect:   httputil.ValidateDenyRedirect(cfg.EntitlementDenyRedirect),
		RenderAppError: s.renderAppError,
	})
}
