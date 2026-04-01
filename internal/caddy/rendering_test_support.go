//go:build unit

package caddy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// handleDenied handles access denied responses for a specific SP config.
// If EntitlementDenyRedirect is configured and valid, redirects to that URL.
// Otherwise, returns 403 Forbidden with error page.
// Only used in tests to simulate the deny path directly.
func (s *SAMLDisco) handleDenied(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, subject string) {
	redirect := httputil.ValidateDenyRedirect(spConfig.EntitlementDenyRedirect)
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	accessDeniedError := &domain.AppError{
		Code:    domain.ErrCodeBadRequest,
		Message: "Access denied by entitlements policy",
		Cause:   domain.ErrAccessDenied,
	}
	statusCode := http.StatusForbidden
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(httputil.NewJSONErrorResponse(accessDeniedError))
		return
	}
	renderer := s.templateRendererFor(spConfig)
	if renderer == nil {
		http.Error(w, accessDeniedError.Message, statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	renderer.RenderError(w, discovery.ErrorData{
		Title:   "Access Denied",
		Message: accessDeniedError.Message,
	})
}
