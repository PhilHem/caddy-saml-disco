// Package authentication contains SAML SP authentication logic: AuthnRequest
// generation and Assertion Consumer Service (ACS) response processing.
//
// The AuthHandler struct is framework-agnostic and is designed to be called by
// the Caddy adapter (internal/caddy). Post-authentication actions such as
// session cookie writing and access-denied rendering are handled via callbacks
// to avoid a dependency on internal/caddy.
package authentication

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

// AuthConfig holds the fields needed by AuthHandler that come from SP-level config.
type AuthConfig struct {
	// EntityID is the SAML SP entity ID.
	EntityID string

	// ACSURL is the explicit ACS URL. If empty, the handler derives it from the request.
	ACSURL string

	// SessionDuration is how long a newly-created session is valid.
	SessionDuration time.Duration

	// RequireEntitlement is an optional role name. When set, the user must hold
	// this role in their EntitlementResult or they are denied.
	RequireEntitlement string
}

// OnAuthenticatedFunc is called after a successful SAML assertion is validated,
// with the session token freshly created by the SessionStore.
// The callee is responsible for writing the session cookie and redirecting.
type OnAuthenticatedFunc func(w http.ResponseWriter, r *http.Request, token string, session *domain.Session)

// OnDeniedFunc is called when an authenticated subject fails the entitlement check.
// The callee is responsible for writing the denied response.
type OnDeniedFunc func(w http.ResponseWriter, r *http.Request, subject string)

// OnErrorFunc is called whenever a handler encounters an application error.
// The callee is responsible for writing the HTTP error response.
type OnErrorFunc func(w http.ResponseWriter, r *http.Request, err *domain.AppError)

// AuthHandler processes SAML SP metadata and ACS requests.
type AuthHandler struct {
	SAMLService      *samlsvc.SAMLService
	MetadataStore    ports.MetadataStore
	SessionStore     ports.SessionStore
	EntitlementStore ports.EntitlementStore
	MetricsRecorder  ports.MetricsRecorder
	Logger           *zap.Logger
	Config           AuthConfig

	// Post-authentication callbacks injected by the caddy adapter.
	OnAuthenticated OnAuthenticatedFunc
	OnDenied        OnDeniedFunc
	OnError         OnErrorFunc
}

// Metadata writes the SP metadata XML for the given ACS URL.
func (h *AuthHandler) Metadata(w http.ResponseWriter, r *http.Request) {
	if h.SAMLService == nil {
		h.onError(w, r, domain.ConfigError("SAML service is not configured"))
		return
	}

	acsURL := h.resolveACSURL(r)
	metadata, err := h.SAMLService.GenerateSPMetadata(acsURL)
	if err != nil {
		h.onError(w, r, domain.ServiceError("Failed to generate metadata"))
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(metadata)
}

// maxACSBodySize is the upper bound on the raw POST body for the ACS endpoint.
// SAML POST-binding responses are base64-encoded XML; even large assertions are
// well under 1 MB. 10 MB provides generous headroom while preventing OOM from
// deliberately oversized requests.
const maxACSBodySize = 10 * 1024 * 1024 // 10 MB

// ACS processes a SAML POST-binding response at the Assertion Consumer Service endpoint.
// Returns a non-nil error only for unexpected infrastructure failures; SAML-level
// failures (bad response, unknown IdP, denied user) are handled via the callbacks
// and always return nil.
func (h *AuthHandler) ACS(w http.ResponseWriter, r *http.Request) error {
	if h.SAMLService == nil {
		h.onError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}
	if h.MetadataStore == nil {
		h.onError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	// Limit body size before parsing to prevent OOM from oversized POST bodies.
	r.Body = http.MaxBytesReader(w, r.Body, maxACSBodySize)

	// Parse form to get SAMLResponse.
	if err := r.ParseForm(); err != nil {
		h.onError(w, r, domain.BadRequestError("Invalid form data"))
		return err
	}

	samlResponse := r.PostForm.Get("SAMLResponse")
	if samlResponse == "" {
		h.onError(w, r, domain.BadRequestError("Invalid SAML response"))
		return domain.BadRequestError("missing SAMLResponse parameter")
	}

	// Extract Issuer from the SAML response to identify the IdP.
	issuer, err := samlsvc.ExtractResponseIssuer(samlResponse)
	if err != nil {
		h.logger().Warn("failed to extract issuer from SAML response",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.onError(w, r, domain.BadRequestError("Invalid SAML response"))
		return err
	}

	// Look up IdP by Issuer entity ID.
	// If the primary lookup fails (e.g. metadata was refreshed after the AuthnRequest
	// was dispatched), attempt to recover the original entity ID from the request store
	// using the InResponseTo field of the SAML response.
	idp, err := h.MetadataStore.GetIdP(issuer)
	if err != nil {
		// Attempt fallback: recover entity ID stored alongside the request ID.
		if store := h.SAMLService.GetEntityIDStore(); store != nil {
			inResponseTo, extractErr := samlsvc.ExtractResponseInResponseTo(samlResponse)
			if extractErr == nil && inResponseTo != "" {
				if storedEntityID, found := store.GetEntityID(inResponseTo); found && storedEntityID != "" {
					fallbackIdP, fallbackErr := h.MetadataStore.GetIdP(storedEntityID)
					if fallbackErr == nil {
						h.logger().Info("ACS IdP lookup recovered via stored entity ID",
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
		h.logger().Warn("unknown IdP issuer in SAML response",
			zap.String("issuer", issuer),
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr),
		)
		h.onError(w, r, domain.AuthError("Unknown identity provider", err))
		return err
	}

	acsURL := h.resolveACSURL(r)
	start := time.Now()
	result, err := h.SAMLService.HandleACS(r, acsURL, idp)
	duration := time.Since(start)
	if err != nil {
		details := ParseSAMLError(err)
		category := string(details.Category)

		// Build structured log fields.
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
		h.logger().Warn("saml authentication failed", fields...)

		h.metricsRecorder().RecordAuthAttempt(idp.EntityID, false)
		h.metricsRecorder().RecordAuthFailure(category, idp.EntityID)
		h.metricsRecorder().RecordAuthDuration(idp.EntityID, "failure", duration)
		h.onError(w, r, domain.AuthError("SAML authentication failed", err))
		return nil
	}

	h.logger().Info("saml authentication successful",
		zap.String("subject", result.Subject),
		zap.String("idp_entity_id", result.IdPEntityID),
	)
	h.metricsRecorder().RecordAuthAttempt(result.IdPEntityID, true)
	h.metricsRecorder().RecordAuthSuccess(result.IdPEntityID)
	h.metricsRecorder().RecordAuthDuration(result.IdPEntityID, "success", duration)

	// Build the session.
	session := &domain.Session{
		Subject:      result.Subject,
		Attributes:   result.Attributes,
		IdPEntityID:  result.IdPEntityID,
		NameIDFormat: result.NameIDFormat,
		SessionIndex: result.SessionIndex,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(h.Config.SessionDuration),
	}

	// Entitlement gate — must run before issuing a session cookie.
	if h.EntitlementStore != nil {
		entitlementResult, err := h.EntitlementStore.Lookup(session.Subject)
		if err != nil {
			if errors.Is(err, domain.ErrEntitlementNotFound) {
				h.onDenied(w, r, session.Subject)
				return nil
			}
			h.logger().Error("entitlement lookup failed",
				zap.Error(err),
				zap.String("subject", session.Subject))
			h.onError(w, r, domain.ServiceError("Failed to check entitlements"))
			return err
		}

		if h.Config.RequireEntitlement != "" {
			hasRole := false
			for _, role := range entitlementResult.Roles {
				if role == h.Config.RequireEntitlement {
					hasRole = true
					break
				}
			}
			if !hasRole {
				h.onDenied(w, r, session.Subject)
				return nil
			}
		}
	}

	if h.SessionStore == nil {
		h.onError(w, r, domain.ConfigError("Session store is not configured"))
		return nil
	}
	token, err := h.SessionStore.Create(session)
	if err != nil {
		h.onError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}
	h.metricsRecorder().RecordSessionCreated()

	// Delegate cookie writing and redirect to the caller.
	if h.OnAuthenticated != nil {
		h.OnAuthenticated(w, r, token, session)
	}
	return nil
}

// resolveACSURL returns the configured ACS URL or derives it from the request.
func (h *AuthHandler) resolveACSURL(r *http.Request) *url.URL {
	if h.Config.ACSURL != "" {
		u, err := url.Parse(h.Config.ACSURL)
		if err == nil {
			return u
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   "/saml/acs",
	}
}

// logger returns the configured logger or a no-op logger.
func (h *AuthHandler) logger() *zap.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return zap.NewNop()
}

// metricsRecorder returns the configured recorder or a no-op recorder.
func (h *AuthHandler) metricsRecorder() ports.MetricsRecorder {
	if h.MetricsRecorder != nil {
		return h.MetricsRecorder
	}
	return &noopMetricsRecorder{}
}

// onError calls OnError if set; otherwise writes a plain 500.
func (h *AuthHandler) onError(w http.ResponseWriter, r *http.Request, err *domain.AppError) {
	if h.OnError != nil {
		h.OnError(w, r, err)
		return
	}
	http.Error(w, err.Message, http.StatusInternalServerError)
}

// onDenied calls OnDenied if set; otherwise writes a 403.
func (h *AuthHandler) onDenied(w http.ResponseWriter, r *http.Request, subject string) {
	if h.OnDenied != nil {
		h.OnDenied(w, r, subject)
		return
	}
	http.Error(w, "Access denied", http.StatusForbidden)
}

// noopMetricsRecorder satisfies ports.MetricsRecorder with no-op methods.
type noopMetricsRecorder struct{}

func (n *noopMetricsRecorder) RecordAuthAttempt(string, bool)              {}
func (n *noopMetricsRecorder) RecordAuthSuccess(string)                    {}
func (n *noopMetricsRecorder) RecordAuthFailure(string, string)            {}
func (n *noopMetricsRecorder) RecordAuthDuration(string, string, time.Duration) {}
func (n *noopMetricsRecorder) RecordSessionCreated()                       {}
func (n *noopMetricsRecorder) RecordSessionValidation(bool)                {}
func (n *noopMetricsRecorder) RecordMetadataRefresh(string, bool, int)     {}
