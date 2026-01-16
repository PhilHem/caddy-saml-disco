package caddy

import (
	"encoding/json"
	"net/http"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"go.uber.org/zap"
)

// handlers_discovery.go - IdP discovery handlers (List and Select)

func (s *SAMLDisco) handleListIdPsInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	// Get optional search filter from query parameter
	filter := r.URL.Query().Get("q")

	idps, err := cfg.metadataStore.ListIdPs(filter)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to list identity providers"))
		return err
	}

	// Return empty array instead of null for empty list
	if idps == nil {
		idps = []domain.IdPInfo{}
	}

	// Localize IdPs based on Accept-Language header
	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	idps = localizeIdPList(idps, langPrefs, cfg.DefaultLanguage)

	// Separate pinned IdPs from the main list
	pinnedIdPs, filteredIdPs := s.separatePinnedIdPsForSP(cfg, idps)

	// Log warning if metadata filtering results in empty list
	if len(filteredIdPs) == 0 && len(idps) > 0 {
		s.getLogger().Warn("empty IdP list after filtering",
			zap.Int("total_idps", len(idps)),
			zap.Int("pinned_idps", len(pinnedIdPs)),
			zap.String("filter", filter),
		)
	}

	response := idpListResponse{
		IdPs:          filteredIdPs,
		PinnedIdPs:    pinnedIdPs,
		RememberedIdP: s.getRememberIdPCookieForSP(r, cfg),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

func (s *SAMLDisco) handleSelectIdPInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	// Parse JSON request body
	var req selectIdPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.renderAppError(w, r, domain.BadRequestError("Request body is invalid"))
		return nil
	}

	// Validate entity_id is provided
	if req.EntityID == "" {
		s.renderAppError(w, r, domain.BadRequestError("entity_id is required"))
		return nil
	}

	// Look up IdP in metadata store
	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idp, err := cfg.metadataStore.GetIdP(req.EntityID)
	if err != nil {
		s.getLogger().Debug("idp not found",
			zap.String("entity_id", req.EntityID),
			zap.Error(err),
		)
		s.renderAppError(w, r, domain.IdPNotFoundError(req.EntityID))
		return nil
	}

	s.getLogger().Info("idp selected for authentication",
		zap.String("entity_id", req.EntityID),
	)

	// Only remember the selected IdP if explicitly requested (BREAKING CHANGE)
	if req.Remember {
		s.setRememberIdPCookieForSP(w, r, cfg, req.EntityID)
	}

	// Check SAML service is configured
	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	// Determine RelayState (return URL after authentication)
	relayState := req.ReturnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	// Determine if forceAuthn is needed based on return URL path
	opts := &domain.AuthnOptions{
		ForceAuthn: cfg.ForceAuthn || MatchesForceAuthnPath(relayState, cfg.ForceAuthnPaths),
	}

	// Compute ACS URL and start SAML auth
	acsURL := s.resolveAcsURLForSP(r, cfg)
	redirectURL, err := cfg.samlService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		s.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return nil
	}

	// Return JSON with redirect URL (instead of 302 which causes fetch issues)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": redirectURL.String(),
	})
	return nil
}

// separatePinnedIdPsForSP separates pinned IdPs from the main list for a specific SP config.
func (s *SAMLDisco) separatePinnedIdPsForSP(spConfig *SPConfig, idps []domain.IdPInfo) ([]domain.IdPInfo, []domain.IdPInfo) {
	return domain.SeparatePinnedIdPs(idps, spConfig.PinnedIdPs)
}
