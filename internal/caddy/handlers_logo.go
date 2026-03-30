package caddy

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// handlers_logo.go - Logo proxy endpoint

func (s *SAMLDisco) handleLogoEndpointInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.logoStore == nil {
		http.NotFound(w, r)
		return nil
	}

	// Extract entity ID from path: /saml/api/logo/{entity_id}
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 5 {
		http.NotFound(w, r)
		return nil
	}
	entityID := pathParts[4]

	// Validate that entityID is not empty after path split
	if entityID == "" {
		s.getLogger().Warn("empty entity_id in logo endpoint request",
			zap.String("path", r.URL.Path),
		)
		http.NotFound(w, r)
		return nil
	}

	logo, err := cfg.logoStore.Get(entityID)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}

	w.Header().Set("Content-Type", logo.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 1 day
	w.Write(logo.Data)
	return nil
}
