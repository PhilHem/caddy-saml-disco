package caddy

import (
	"encoding/json"
	"net/http"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// handlers_health.go - Health endpoint handlers

func (s *SAMLDisco) handleHealthInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("metadata store not configured"))
		return nil
	}
	health := cfg.metadataStore.Health()
	resp := HealthResponse{
		Version:        getVersion(),
		GitCommit:      getGitCommit(),
		BuildTime:      getBuildTime(),
		MetadataHealth: health,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	return nil
}

func (s *SAMLDisco) handleSimpleHealthInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("metadata store not configured"))
		return nil
	}
	health := cfg.metadataStore.Health()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
	return nil
}
