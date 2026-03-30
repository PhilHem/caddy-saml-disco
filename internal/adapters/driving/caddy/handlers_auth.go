package caddy

import (
	"errors"
	"net/http"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"go.uber.org/zap"
)

// handlers_auth.go - Authentication handlers (Metadata and ACS)

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

	// Check for empty SAMLResponse
	samlResponse := r.PostForm.Get("SAMLResponse")
	if samlResponse == "" {
		s.renderAppError(w, r, domain.BadRequestError("Invalid SAML response"))
		return domain.BadRequestError("missing SAMLResponse parameter")
	}

	// Extract Issuer from SAML response to find the correct IdP
	issuer, err := ExtractResponseIssuer(samlResponse)
	if err != nil {
		s.getLogger().Warn("failed to extract issuer from SAML response",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		s.renderAppError(w, r, domain.BadRequestError("Invalid SAML response"))
		return err
	}

	// Look up IdP by Issuer entity ID.
	// If the primary lookup fails (e.g. metadata was refreshed after the AuthnRequest
	// was dispatched), attempt to recover the original entity ID from the request store
	// using the InResponseTo field of the SAML response.
	idp, err := cfg.metadataStore.GetIdP(issuer)
	if err != nil {
		// Attempt fallback: recover entity ID stored alongside the request ID.
		if store, ok := cfg.samlService.requestStore.(interface {
			GetEntityID(string) (string, bool)
		}); ok {
			inResponseTo, extractErr := ExtractResponseInResponseTo(samlResponse)
			if extractErr == nil && inResponseTo != "" {
				if storedEntityID, found := store.GetEntityID(inResponseTo); found && storedEntityID != "" {
					fallbackIdP, fallbackErr := cfg.metadataStore.GetIdP(storedEntityID)
					if fallbackErr == nil {
						s.getLogger().Info("ACS IdP lookup recovered via stored entity ID",
							zap.String("issuer", issuer),
							zap.String("stored_entity_id", storedEntityID),
							zap.String("in_response_to", inResponseTo),
						)
						idp = fallbackIdP
						err = nil
					}
				}
			}
		}
	}
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

	// Check entitlements before creating a session cookie.
	// If the user is denied, we must not issue a session.
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

	// Redirect to relay state or default page
	relayState := ValidateRelayState(r.FormValue("RelayState"))
	http.Redirect(w, r, relayState, http.StatusFound)
	return nil
}
