package caddy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"go.uber.org/zap"
)

// Internal handlers - shared implementation for both single-SP and multi-SP modes

func (s *SAMLDisco) handleMetadataInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	acsURL := s.resolveAcsURLForSP(r, cfg)
	metadata, err := cfg.samlService.GenerateSPMetadata(acsURL)
	if err != nil {
		s.renderAppError(w, r, domain.ServiceError("Failed to generate metadata"))
		return err
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(metadata)
	return nil
}

func (s *SAMLDisco) handleACSInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	if cfg.metadataStore == nil {
		s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	// Parse form to get SAMLResponse
	if err := r.ParseForm(); err != nil {
		s.renderAppError(w, r, domain.BadRequestError("Invalid form data"))
		return err
	}

	// Extract Issuer from SAML response to find the correct IdP
	issuer, err := ExtractResponseIssuer(r.PostForm.Get("SAMLResponse"))
	if err != nil {
		s.getLogger().Warn("failed to extract issuer from SAML response",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, domain.BadRequestError("Invalid SAML response"))
		return err
	}

	// Look up IdP by Issuer entity ID
	idp, err := cfg.metadataStore.GetIdP(issuer)
	if err != nil {
		s.getLogger().Warn("unknown IdP issuer in SAML response",
			zap.String("issuer", issuer),
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, domain.AuthError("Unknown identity provider", err))
		return err
	}

	acsURL := s.resolveAcsURLForSP(r, cfg)
	start := time.Now()
	result, err := cfg.samlService.HandleACS(r, acsURL, idp)
	duration := time.Since(start)
	if err != nil {
		details := ParseSAMLError(err)
		category := string(details.Category)

		// Build structured log fields
		// @tra: Adapter.SAMLAuthErrors
		fields := []zap.Field{
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("error_category", category),
			zap.String("idp_entity_id", idp.EntityID),
		}
		if details.PrivateError != "" {
			fields = append(fields, zap.String("private_error", details.PrivateError))
		}
		if details.IdPStatus != nil {
			fields = append(fields, zap.String("idp_status_code", details.IdPStatus.StatusCode))
			if details.IdPStatus.StatusMessage != "" {
				fields = append(fields, zap.String("idp_status_message", details.IdPStatus.StatusMessage))
			}
		}
		if details.TimeContext != nil {
			fields = append(fields, zap.Time("server_time", details.TimeContext.ServerTime))
		}
		s.getLogger().Warn("saml authentication failed", fields...)

		s.getMetricsRecorder().RecordAuthAttempt(idp.EntityID, false)
		s.getMetricsRecorder().RecordAuthFailure(category, idp.EntityID)
		s.getMetricsRecorder().RecordAuthDuration(idp.EntityID, "failure", duration)
		s.renderAppError(w, r, domain.AuthError("SAML authentication failed", err))
		return nil
	}

	s.getLogger().Info("saml authentication successful",
		zap.String("subject", result.Subject),
		zap.String("idp_entity_id", result.IdPEntityID),
	)
	s.getMetricsRecorder().RecordAuthAttempt(result.IdPEntityID, true)
	s.getMetricsRecorder().RecordAuthSuccess(result.IdPEntityID)
	s.getMetricsRecorder().RecordAuthDuration(result.IdPEntityID, "success", duration)

	// Create session
	session := &domain.Session{
		Subject:      result.Subject,
		Attributes:   result.Attributes,
		IdPEntityID:  result.IdPEntityID,
		NameIDFormat: result.NameIDFormat,
		SessionIndex: result.SessionIndex,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(cfg.sessionDuration),
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
	s.getMetricsRecorder().RecordSessionCreated()

	// Set session cookie
	s.setSessionCookieForSP(w, r, cfg, token)

	// Check entitlements if configured
	if cfg.entitlementStore != nil {
		entitlementResult, err := cfg.entitlementStore.Lookup(session.Subject)
		if err != nil {
			// ErrEntitlementNotFound means user is not authorized
			if errors.Is(err, domain.ErrEntitlementNotFound) {
				s.handleDeniedForSP(w, r, cfg, session.Subject)
				return nil
			}
			// Other errors are unexpected
			s.getLogger().Error("entitlement lookup failed",
				zap.Error(err),
				zap.String("subject", session.Subject))
			s.renderAppError(w, r, domain.ServiceError("Failed to check entitlements"))
			return err
		}

		// Check require_entitlement if configured
		if cfg.RequireEntitlement != "" {
			hasRole := false
			for _, role := range entitlementResult.Roles {
				if role == cfg.RequireEntitlement {
					hasRole = true
					break
				}
			}
			if !hasRole {
				s.handleDeniedForSP(w, r, cfg, session.Subject)
				return nil
			}
		}
	}

	// Redirect to relay state or default page
	relayState := ValidateRelayState(r.FormValue("RelayState"))
	http.Redirect(w, r, relayState, http.StatusFound)
	return nil
}

func (s *SAMLDisco) handleLogoutInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.samlService == nil {
		// Fall back to local-only logout
		s.clearSessionCookiesForSP(w, r, cfg)
		returnTo := ValidateRelayState(r.URL.Query().Get("return_to"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	session := GetSession(r)
	returnTo := ValidateRelayState(r.URL.Query().Get("return_to"))

	// If we have a session, try SP-initiated SLO
	if session != nil && cfg.metadataStore != nil {
		idp, err := cfg.metadataStore.GetIdP(session.IdPEntityID)
		if err == nil && idp != nil && idp.SLOURL != "" {
			// IdP supports SLO - redirect to IdP SLO
			sloURL := s.resolveSLOURLForSP(r, cfg)
			logoutURL, err := cfg.samlService.CreateLogoutRequest(session, idp, sloURL, returnTo)
			if err == nil {
				http.Redirect(w, r, logoutURL.String(), http.StatusFound)
				return nil
			}
			// If SLO fails, fall through to local-only logout
			s.getLogger().Warn("failed to create logout request, falling back to local logout",
				zap.Error(err),
			)
		}
	}

	// Fall back to local-only logout (no SLO or SLO failed)
	s.clearSessionCookiesForSP(w, r, cfg)
	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

func (s *SAMLDisco) handleSLOInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	sloURL := s.resolveSLOURLForSP(r, cfg)

	// Check if this is a LogoutResponse (SP-initiated return) or LogoutRequest (IdP-initiated)
	samlResponse := r.URL.Query().Get("SAMLResponse")
	samlRequest := r.URL.Query().Get("SAMLRequest")

	if samlResponse != "" {
		// SP-initiated: IdP is redirecting back with LogoutResponse
		// Get IdP from session or metadata
		session := GetSession(r)
		if session == nil {
			// No session, just redirect
			returnTo := ValidateRelayState(r.URL.Query().Get("RelayState"))
			http.Redirect(w, r, returnTo, http.StatusFound)
			return nil
		}

		if cfg.metadataStore == nil {
			s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
			return nil
		}
		idp, err := cfg.metadataStore.GetIdP(session.IdPEntityID)
		if err != nil {
			s.renderAppError(w, r, domain.ServiceError("Failed to get IdP metadata"))
			return nil
		}

		// Validate LogoutResponse
		err = cfg.samlService.HandleLogoutResponse(r, sloURL, idp)
		if err != nil {
			s.getLogger().Warn("logout response validation failed",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
			)
			// Continue with logout anyway
		}

		// Clear session
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.Config.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		s.clearRememberIdPCookieForSP(w, r, cfg)

		returnTo := ValidateRelayState(r.URL.Query().Get("RelayState"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	if samlRequest != "" {
		// IdP-initiated: IdP is requesting logout
		if cfg.metadataStore == nil {
			s.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
			return nil
		}
		// Get first IdP from metadata store (for IdP-initiated logout, we need to identify the IdP)
		idps, err := cfg.metadataStore.ListIdPs("")
		if err != nil || len(idps) == 0 {
			s.renderAppError(w, r, domain.ConfigError("No identity provider is configured"))
			return nil
		}
		idp := &idps[0]

		// Parse LogoutRequest
		result, err := cfg.samlService.HandleLogoutRequest(r, sloURL, idp)
		if err != nil {
			s.getLogger().Warn("logout request validation failed",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
			)
			s.renderAppError(w, r, domain.AuthError("Logout request validation failed", err))
			return nil
		}

		// Clear session
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.Config.SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
		s.clearRememberIdPCookieForSP(w, r, cfg)

		// Send LogoutResponse back to IdP
		returnTo := ValidateRelayState(r.URL.Query().Get("RelayState"))
		logoutResponseURL, err := cfg.samlService.CreateLogoutResponse(result.RequestID, idp, sloURL, returnTo)
		if err != nil {
			s.renderAppError(w, r, domain.ServiceError("Failed to create logout response"))
			return err
		}
		http.Redirect(w, r, logoutResponseURL.String(), http.StatusFound)
		return nil
	}

	// No SAMLRequest or SAMLResponse - invalid request
	s.renderAppError(w, r, domain.BadRequestError("Missing SAMLRequest or SAMLResponse"))
	return nil
}

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

func (s *SAMLDisco) handleSessionInfoInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	response := sessionInfoResponse{Authenticated: false}

	// Try to get session from cookie
	if cfg.sessionStore != nil {
		cookie, err := r.Cookie(cfg.Config.SessionCookieName)
		if err == nil && cookie.Value != "" {
			session, err := cfg.sessionStore.Get(cookie.Value)
			if err == nil && session != nil {
				response.Authenticated = true
				response.Subject = session.Subject
				response.IdPEntityID = session.IdPEntityID
				response.Attributes = session.Attributes
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

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
	if len(idps) == 1 && cfg.samlService != nil {
		idp := &idps[0]
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

	// Single IdP - check SAML service and redirect directly
	if cfg.samlService == nil {
		s.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return
	}
	idp := &idps[0]

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

// ForSP wrapper methods - these delegate to internal handlers

func (s *SAMLDisco) handleMetadataForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleMetadataInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleACSForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleACSInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleLogoutForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleLogoutInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleSLOForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleSLOInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleListIdPsForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleListIdPsInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleSelectIdPForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleSelectIdPInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleSessionInfoForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleSessionInfoInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleHealthForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleHealthInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleSimpleHealthForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleSimpleHealthInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleLogoEndpointForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleLogoEndpointInternal(w, r, spConfig)
}

func (s *SAMLDisco) handleDiscoveryUIForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) error {
	return s.handleDiscoveryUIInternal(w, r, spConfig)
}

func (s *SAMLDisco) redirectToIdPForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) {
	s.redirectToIdPInternal(w, r, spConfig)
}

// separatePinnedIdPsForSP separates pinned IdPs from the main list for a specific SP config.
func (s *SAMLDisco) separatePinnedIdPsForSP(spConfig *SPConfig, idps []domain.IdPInfo) ([]domain.IdPInfo, []domain.IdPInfo) {
	return domain.SeparatePinnedIdPs(idps, spConfig.PinnedIdPs)
}
