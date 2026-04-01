// Package logout provides the LogoutHandler that encapsulates all SAML
// Single Logout (SLO) and local logout logic.
//
// It is a self-contained feature slice: it imports from domain/, ports/, httputil/,
// and saml/ but never from internal/caddy/, keeping the dependency direction clean.
package logout

import (
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// LogoutHandler handles SP-initiated logout (/saml/logout) and SAML Single
// Logout (/saml/slo) for a single SP configuration.
type LogoutHandler struct {
	// MetadataStore is used to look up IdP metadata during logout flows.
	MetadataStore ports.MetadataStore

	// SAMLService performs SAML protocol operations (creating LogoutRequests,
	// validating LogoutResponses, etc.).
	SAMLService *samlsvc.SAMLService

	// Logger receives structured diagnostic messages.
	Logger *zap.Logger

	// ClearSessionCookies removes the session (and remember-IdP) cookies from
	// the response. The exact cookie names and attributes are controlled by the
	// caller; the LogoutHandler just invokes this function at the right time.
	ClearSessionCookies func(w http.ResponseWriter, r *http.Request)

	// RenderAppError writes an error response (HTML for browser endpoints, JSON
	// for /saml/api/* paths) appropriate to the request.
	RenderAppError func(w http.ResponseWriter, r *http.Request, err *domain.AppError)

	// ValidateRelayState sanitises an untrusted relay-state value and returns a
	// safe relative path (defaults to "/" on any violation).
	ValidateRelayState func(relayState string) string

	// ResolveSLOURL computes the absolute SLO URL for the current request. The
	// returned URL is passed to SAMLService methods that need it.
	ResolveSLOURL func(r *http.Request) *url.URL

	// GetSession retrieves the authenticated session stored in the request
	// context, returning nil for unauthenticated requests.
	GetSession func(r *http.Request) *domain.Session
}

// logger returns the logger or a no-op logger when none is set.
func (h *LogoutHandler) logger() *zap.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return zap.NewNop()
}

// Logout handles GET /saml/logout.
//
// When the session has an associated IdP that supports SLO, it initiates an
// SP-initiated LogoutRequest redirect to the IdP. Otherwise it falls back to
// clearing session cookies locally and redirecting to the return_to URL.
func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) error {
	if h.SAMLService == nil {
		// No SAML service — local-only logout.
		h.ClearSessionCookies(w, r)
		returnTo := h.ValidateRelayState(r.URL.Query().Get("return_to"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	session := h.GetSession(r)
	returnTo := h.ValidateRelayState(r.URL.Query().Get("return_to"))

	// If we have a session, attempt SP-initiated SLO.
	if session != nil && h.MetadataStore != nil {
		idp, err := h.MetadataStore.GetIdP(session.IdPEntityID)
		if err == nil && idp != nil && idp.SLOURL != "" {
			sloURL := h.ResolveSLOURL(r)
			logoutURL, err := h.SAMLService.CreateLogoutRequest(session, idp, sloURL, returnTo)
			if err == nil {
				http.Redirect(w, r, logoutURL.String(), http.StatusFound)
				return nil
			}
			// SLO request creation failed — fall through to local logout.
			h.logger().Warn("failed to create logout request, falling back to local logout",
				zap.Error(err),
			)
		}
	}

	// Fall back to local-only logout.
	h.ClearSessionCookies(w, r)
	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

// SLO handles GET (and POST) /saml/slo.
//
// It distinguishes three cases based on query parameters:
//   - SAMLResponse present: SP-initiated flow returning from IdP — validate and clear session.
//   - SAMLRequest present:  IdP-initiated flow — validate, clear session, send LogoutResponse.
//   - Neither present:      invalid request — render 400.
func (h *LogoutHandler) SLO(w http.ResponseWriter, r *http.Request) error {
	if h.SAMLService == nil {
		h.RenderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	sloURL := h.ResolveSLOURL(r)

	samlResponse := r.URL.Query().Get("SAMLResponse")
	samlRequest := r.URL.Query().Get("SAMLRequest")

	if samlResponse != "" {
		return h.handleLogoutResponse(w, r, sloURL)
	}

	if samlRequest != "" {
		return h.handleLogoutRequest(w, r, sloURL)
	}

	// Neither parameter is present.
	h.RenderAppError(w, r, domain.BadRequestError("Missing SAMLRequest or SAMLResponse"))
	return nil
}

// handleLogoutResponse processes a SAMLResponse (SP-initiated SLO return from IdP).
func (h *LogoutHandler) handleLogoutResponse(w http.ResponseWriter, r *http.Request, sloURL *url.URL) error {
	session := h.GetSession(r)
	if session == nil {
		// No active session — just redirect.
		returnTo := h.ValidateRelayState(r.URL.Query().Get("RelayState"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return nil
	}

	if h.MetadataStore == nil {
		h.RenderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idp, err := h.MetadataStore.GetIdP(session.IdPEntityID)
	if err != nil {
		h.RenderAppError(w, r, domain.ServiceError("Failed to get IdP metadata"))
		return nil
	}

	if err := h.SAMLService.HandleLogoutResponse(r, sloURL, idp); err != nil {
		h.logger().Warn("logout response validation failed",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		// Continue with logout even when validation fails.
	}

	h.ClearSessionCookies(w, r)

	returnTo := h.ValidateRelayState(r.URL.Query().Get("RelayState"))
	http.Redirect(w, r, returnTo, http.StatusFound)
	return nil
}

// handleLogoutRequest processes a SAMLRequest (IdP-initiated SLO).
func (h *LogoutHandler) handleLogoutRequest(w http.ResponseWriter, r *http.Request, sloURL *url.URL) error {
	if h.MetadataStore == nil {
		h.RenderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	// Decode the SAMLRequest so we can extract the Issuer element and identify
	// which IdP sent the LogoutRequest. Using ListIdPs("")[0] would select the
	// wrong IdP when more than one IdP is configured.
	xmlBytes, err := domain.DecodeSAMLRequest(r.URL.Query().Get("SAMLRequest"))
	if err != nil {
		h.logger().Warn("failed to decode SAMLRequest",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.RenderAppError(w, r, domain.BadRequestError("Invalid SAMLRequest encoding"))
		return nil
	}

	doc := etree.NewDocument()
	if parseErr := doc.ReadFromBytes(xmlBytes); parseErr != nil || doc.Root() == nil {
		h.logger().Warn("failed to parse LogoutRequest XML",
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.RenderAppError(w, r, domain.BadRequestError("Invalid LogoutRequest XML"))
		return nil
	}

	// Extract Issuer — try both namespace-prefixed and plain forms.
	var issuerText string
	root := doc.Root()
	for _, tag := range []string{"saml:Issuer", "Issuer"} {
		if el := root.FindElement(tag); el != nil {
			issuerText = el.Text()
			break
		}
	}
	if issuerText == "" {
		h.logger().Warn("LogoutRequest has no Issuer element",
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.RenderAppError(w, r, domain.BadRequestError("LogoutRequest missing Issuer"))
		return nil
	}

	idp, err := h.MetadataStore.GetIdP(issuerText)
	if err != nil {
		h.logger().Warn("unknown IdP in LogoutRequest",
			zap.String("issuer", issuerText),
			zap.Error(err),
		)
		h.RenderAppError(w, r, domain.BadRequestError("Unknown identity provider"))
		return nil
	}

	result, err := h.SAMLService.HandleLogoutRequest(r, sloURL, idp)
	if err != nil {
		h.logger().Warn("logout request validation failed",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.RenderAppError(w, r, domain.AuthError("Logout request validation failed", err))
		return nil
	}

	h.ClearSessionCookies(w, r)

	returnTo := h.ValidateRelayState(r.URL.Query().Get("RelayState"))
	logoutResponseURL, err := h.SAMLService.CreateLogoutResponse(result.RequestID, idp, sloURL, returnTo)
	if err != nil {
		h.RenderAppError(w, r, domain.ServiceError("Failed to create logout response"))
		return err
	}
	http.Redirect(w, r, logoutResponseURL.String(), http.StatusFound)
	return nil
}
