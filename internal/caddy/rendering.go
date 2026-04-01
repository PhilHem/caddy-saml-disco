package caddy

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func (s *SAMLDisco) renderHTTPError(w http.ResponseWriter, statusCode int, title, message string) {
	renderer := s.templateRendererFor(nil)
	if renderer == nil {
		http.Error(w, message, statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	renderer.RenderError(w, discovery.ErrorData{Title: title, Message: message})
}

func (s *SAMLDisco) templateRendererFor(sp *SPConfig) *discovery.TemplateRenderer {
	if sp != nil && sp.templateRenderer != nil {
		return sp.templateRenderer
	}
	if s.registry != nil {
		if wildcard := s.registry.GetByHostname(""); wildcard != nil {
			return wildcard.templateRenderer
		}
	}
	return nil
}

func (s *SAMLDisco) renderAppError(w http.ResponseWriter, r *http.Request, err *domain.AppError) {
	statusCode := httputil.HTTPStatusForCode(err.Code)
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(httputil.NewJSONErrorResponse(err))
		return
	}
	s.renderHTTPError(w, statusCode, httputil.TitleForCode(err.Code), err.Message)
}
