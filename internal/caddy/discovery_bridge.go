package caddy

import (
	"net/http"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func (s *SAMLDisco) discoveryAdapter(cfg *SPConfig) *discovery.HTTPAdapter {
	var rememberIdPDuration time.Duration
	if cfg.Config.RememberIdPDuration != "" {
		if d, err := httputil.ParseDuration(cfg.Config.RememberIdPDuration); err == nil {
			rememberIdPDuration = d
		}
	}
	altLogins := make([]discovery.AltLoginConfig, len(cfg.AltLogins))
	for i, alt := range cfg.AltLogins {
		altLogins[i] = discovery.AltLoginConfig{URL: alt.URL, Label: alt.Label}
	}
	// Nil *SAMLService would produce a non-nil interface value — assign only when set.
	var samlSvc discovery.AuthStarter
	if cfg.samlService != nil {
		samlSvc = cfg.samlService
	}
	return discovery.NewHTTPAdapter(discovery.AdapterDeps{
		MetadataStore:         cfg.metadataStore,
		SessionStore:          cfg.sessionStore,
		SAMLService:           samlSvc,
		Renderer:              cfg.templateRenderer,
		Logger:                s.getLogger(),
		DefaultLanguage:       cfg.Config.DefaultLanguage,
		PinnedIdPs:            cfg.Config.PinnedIdPs,
		BypassIdPs:            cfg.Config.BypassIdPs,
		GuestAccessLabel:      cfg.Config.GuestAccessLabel,
		AltLogins:             altLogins,
		ServiceName:           cfg.Config.ServiceName,
		ForceAuthn:            cfg.Config.ForceAuthn,
		ForceAuthnPaths:       cfg.Config.ForceAuthnPaths,
		RememberIdPCookieName: cfg.Config.RememberIdPCookieName,
		RememberIdPDuration:   rememberIdPDuration,
		SessionCookieName:     cfg.Config.SessionCookieName,
		SessionCookieDomain:   cfg.Hostname,
		SessionDuration:       cfg.sessionDuration,
		AcsURL:                cfg.Config.AcsURL,
		LoginRedirect:         cfg.Config.LoginRedirect,
		CookieSecure:          cfg.Config.CookieSecure,
	})
}

func (s *SAMLDisco) handleListIdPsInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.discoveryAdapter(cfg).HandleListIdPs(w, r)
}

func (s *SAMLDisco) handleSelectIdPInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.discoveryAdapter(cfg).HandleSelectIdP(w, r)
}

func (s *SAMLDisco) handleDiscoveryUIInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	return s.discoveryAdapter(cfg).HandleDiscoveryUI(w, r)
}

func (s *SAMLDisco) redirectToIdPInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) {
	s.discoveryAdapter(cfg).HandleRedirectToIdP(w, r)
}
