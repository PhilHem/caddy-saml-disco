package caddy

import (
	"encoding/json"
	"net/http"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
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

func (s *SAMLDisco) handleHealthForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleHealthInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleSimpleHealthForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleSimpleHealthInternal(w, r, spConfig)
}
