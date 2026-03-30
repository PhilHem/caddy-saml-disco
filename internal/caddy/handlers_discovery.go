package caddy

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/domain"
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

	// Append guest access entry to end of regular IdPs if configured
	if cfg.GuestAccessLabel != "" {
		filteredIdPs = append(filteredIdPs, domain.IdPInfo{
			EntityID:    GuestEntityID,
			DisplayName: cfg.GuestAccessLabel,
		})
	}

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

	// Handle guest access — no metadata lookup needed
	if req.EntityID == GuestEntityID && cfg.GuestAccessLabel != "" {
		return s.handleGuestAccess(w, r, cfg, req.ReturnURL)
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

	// Check if this is a bypass IdP - skip SAML and create session directly
	if isBypassIdP(cfg, req.EntityID) {
		return s.handleBypassIdP(w, r, cfg, idp, req.ReturnURL)
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

// isBypassIdP checks if the given entity ID is configured as a bypass IdP.
func isBypassIdP(cfg *SPConfig, entityID string) bool {
	for _, id := range cfg.BypassIdPs {
		if id == entityID {
			return true
		}
	}
	return false
}

// handleBypassIdP creates a guest session for a bypass IdP without SAML authentication.
func (s *SAMLDisco) handleBypassIdP(w http.ResponseWriter, r *http.Request, cfg *SPConfig, idp *domain.IdPInfo, returnURL string) error {
	s.getLogger().Info("bypass idp selected, creating guest session",
		zap.String("entity_id", idp.EntityID),
	)

	relayState := returnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	// Create a guest session
	session := &domain.Session{
		Subject:     "guest",
		IdPEntityID: idp.EntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(cfg.sessionDuration),
	}

	if cfg.sessionStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Session store is not configured"))
		return nil
	}
	token, err := cfg.sessionStore.Create(session)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}

	s.setSessionCookieForSP(w, r, cfg, token)

	// Return JSON with redirect URL (same format as normal SAML flow)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": relayState,
	})
	return nil
}

// handleGuestAccess creates a guest session without any SAML authentication.
// Unlike handleBypassIdP, this does not require an IdP to exist in metadata.
func (s *SAMLDisco) handleGuestAccess(w http.ResponseWriter, r *http.Request, cfg *SPConfig, returnURL string) error {
	s.getLogger().Info("guest access selected, creating guest session")

	relayState := returnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	session := &domain.Session{
		Subject:     "guest",
		IdPEntityID: GuestEntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(cfg.sessionDuration),
	}

	if cfg.sessionStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Session store is not configured"))
		return nil
	}
	token, err := cfg.sessionStore.Create(session)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}

	s.setSessionCookieForSP(w, r, cfg, token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": relayState,
	})
	return nil
}

// separatePinnedIdPsForSP separates pinned IdPs from the main list for a specific SP config.
func (s *SAMLDisco) separatePinnedIdPsForSP(spConfig *SPConfig, idps []domain.IdPInfo) ([]domain.IdPInfo, []domain.IdPInfo) {
	return domain.SeparatePinnedIdPs(idps, spConfig.PinnedIdPs)
}
