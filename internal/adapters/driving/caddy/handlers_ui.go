package caddy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// handlers_ui.go - Discovery UI and redirect handlers

func (s *SAMLDisco) handleDiscoveryUIInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idps, err := cfg.metadataStore.ListIdPs("")
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	// Get return_url from query param (where to redirect after auth)
	returnURL := ValidateRelayState(r.URL.Query().Get("return_url"))

	// Auto-redirect if only one IdP
	if len(idps) == 1 {
		idp := &idps[0]

		// If this is a bypass IdP, create session directly
		if isBypassIdP(cfg, idp.EntityID) {
			return s.handleBypassIdP(w, r, cfg, idp, returnURL)
		}

		if cfg.samlService != nil {
			acsURL := s.resolveAcsURLForSP(r, cfg)

			// Determine if forceAuthn is needed based on return URL path
			opts := &domain.AuthnOptions{
				ForceAuthn: cfg.ForceAuthn || MatchesForceAuthnPath(returnURL, cfg.ForceAuthnPaths),
			}

			redirectURL, err := cfg.samlService.StartAuthWithOptions(idp, acsURL, returnURL, opts)
			if err != nil {
				s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
				return nil
			}
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return nil
		}
	}

	// Serve discovery UI HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return s.renderDiscoveryHTMLForSP(w, r, cfg, idps, returnURL)
}

func (s *SAMLDisco) redirectToIdPInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) {
	// If LoginRedirect is configured, redirect to custom UI
	if cfg.LoginRedirect != "" {
		redirectURL := cfg.LoginRedirect
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Check if metadata store is configured
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return
	}

	// Get IdPs from metadata store
	idps, err := cfg.metadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		s.renderAppError(w, r, domain.ConfigError("No identity provider is configured"))
		return
	}

	// Multiple IdPs - redirect to discovery page for user selection
	if len(idps) > 1 {
		redirectURL := "/saml/disco?return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Single IdP - bypass or SAML redirect
	idp := &idps[0]

	// If this is a bypass IdP, create session directly
	if isBypassIdP(cfg, idp.EntityID) {
		s.handleBypassIdP(w, r, cfg, idp, r.URL.RequestURI())
		return
	}

	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return
	}

	// Compute ACS URL and use original URL as RelayState
	acsURL := s.resolveAcsURLForSP(r, cfg)
	relayState := r.URL.RequestURI()

	// Determine if forceAuthn is needed
	opts := &domain.AuthnOptions{
		ForceAuthn: cfg.ForceAuthn || MatchesForceAuthnPath(r.URL.Path, cfg.ForceAuthnPaths),
	}

	// Generate AuthnRequest and redirect URL
	redirectURL, err := cfg.samlService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
