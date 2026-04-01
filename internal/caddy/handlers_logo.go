package caddy

import (
	"net/http"
)

const logoPathPrefix = "/saml/api/logo/"

func (s *SAMLDisco) handleLogoEndpointInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.logoStore == nil || len(r.URL.Path) <= len(logoPathPrefix) {
		http.NotFound(w, r)
		return nil
	}
	entityID := r.URL.Path[len(logoPathPrefix):]
	logo, err := cfg.logoStore.Get(entityID)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	w.Header().Set("Content-Type", logo.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logo.Data)
	return nil
}
