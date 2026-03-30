package caddy

import (
	"net/http"

	"github.com/beevik/etree"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"go.uber.org/zap"
)

// handlers_logout.go - Logout and SLO handlers

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
		s.clearSessionCookiesForSP(w, r, cfg)

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

		// Decode the SAMLRequest and extract the Issuer to identify which IdP is
		// sending the LogoutRequest. Using ListIdPs("")[0] would select the wrong
		// IdP whenever more than one IdP is configured.
		xmlBytes, err := domain.DecodeSAMLRequest(samlRequest)
		if err != nil {
			s.getLogger().Warn("failed to decode SAMLRequest",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
			)
			s.renderAppError(w, r, domain.BadRequestError("Invalid SAMLRequest encoding"))
			return nil
		}

		doc := etree.NewDocument()
		if parseErr := doc.ReadFromBytes(xmlBytes); parseErr != nil || doc.Root() == nil {
			s.getLogger().Warn("failed to parse LogoutRequest XML",
				zap.String("remote_addr", r.RemoteAddr),
			)
			s.renderAppError(w, r, domain.BadRequestError("Invalid LogoutRequest XML"))
			return nil
		}

		// Extract Issuer: try both namespace-prefixed and plain forms.
		var issuerText string
		root := doc.Root()
		for _, tag := range []string{"saml:Issuer", "Issuer"} {
			if el := root.FindElement(tag); el != nil {
				issuerText = el.Text()
				break
			}
		}
		if issuerText == "" {
			s.getLogger().Warn("LogoutRequest has no Issuer element",
				zap.String("remote_addr", r.RemoteAddr),
			)
			s.renderAppError(w, r, domain.BadRequestError("LogoutRequest missing Issuer"))
			return nil
		}

		idp, err := cfg.metadataStore.GetIdP(issuerText)
		if err != nil {
			s.getLogger().Warn("unknown IdP in LogoutRequest",
				zap.String("issuer", issuerText),
				zap.Error(err),
			)
			s.renderAppError(w, r, domain.BadRequestError("Unknown identity provider"))
			return nil
		}

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
		s.clearSessionCookiesForSP(w, r, cfg)

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
