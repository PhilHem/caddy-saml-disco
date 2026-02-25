package caddy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Rendering methods for SAMLDisco.
// These methods handle HTML and JSON error rendering, discovery UI, and access denied responses.

// renderDiscoveryHTML renders the discovery UI HTML page.
func (s *SAMLDisco) renderDiscoveryHTML(w http.ResponseWriter, r *http.Request, idps []domain.IdPInfo, returnURL string) error {
	// Localize IdPs based on Accept-Language header
	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	defaultLang := s.getDefaultLanguage()
	localizedIdPs := localizeIdPList(idps, langPrefs, defaultLang)

	// Separate pinned IdPs from the main list
	pinnedIdPs, filteredIdPs := s.separatePinnedIdPs(localizedIdPs)

	// Append guest access entry to pinned IdPs if configured
	if s.GuestAccessLabel != "" {
		pinnedIdPs = append(pinnedIdPs, domain.IdPInfo{
			EntityID:    GuestEntityID,
			DisplayName: s.GuestAccessLabel,
		})
	}

	// Get the remembered IdP entity ID
	rememberedIdPID := s.getRememberIdPCookie(r)

	// Look up full IdP info for the remembered IdP (and localize it)
	var rememberedIdP *domain.IdPInfo
	if rememberedIdPID != "" && s.metadataStore != nil {
		if idp, err := s.metadataStore.GetIdP(rememberedIdPID); err == nil {
			localized := domain.LocalizeIdPInfo(*idp, langPrefs, defaultLang)
			rememberedIdP = &localized
		}
	}

	// Convert alt login config to template data
	altLogins := make([]AltLoginOption, len(s.AltLogins))
	for i, alt := range s.AltLogins {
		altLogins[i] = AltLoginOption{URL: alt.URL, Label: alt.Label}
	}

	return s.templateRenderer.RenderDisco(w, DiscoData{
		IdPs:            filteredIdPs,
		PinnedIdPs:      pinnedIdPs,
		ReturnURL:       returnURL,
		RememberedIdPID: rememberedIdPID,
		RememberedIdP:   rememberedIdP,
		AltLogins:       altLogins,
		ServiceName:     s.ServiceName,
	})
}

// renderHTTPError renders an HTML error page with the given status code, title, and message.
// This provides user-friendly error pages instead of plain text http.Error responses.
// Falls back to plain text if template renderer is not configured.
func (s *SAMLDisco) renderHTTPError(w http.ResponseWriter, statusCode int, title, message string) {
	// Fall back to plain text if template renderer is not configured
	if s.templateRenderer == nil {
		http.Error(w, message, statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	// RenderError uses html/template which auto-escapes to prevent XSS
	s.templateRenderer.RenderError(w, ErrorData{
		Title:   title,
		Message: message,
	})
}

// handleDenied handles access denied responses.
// If EntitlementDenyRedirect is configured and valid, redirects to that URL.
// Otherwise, returns 403 Forbidden with error page.
func (s *SAMLDisco) handleDenied(w http.ResponseWriter, r *http.Request, subject string) {
	redirect := ValidateDenyRedirect(s.EntitlementDenyRedirect)
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	// Default 403 with error page
	// Create a custom AppError with 403 status (Forbidden)
	accessDeniedError := &domain.AppError{
		Code:    domain.ErrCodeBadRequest, // Use BadRequest as base, but override status
		Message: "Access denied by entitlements policy",
		Cause:   domain.ErrAccessDenied,
	}
	// Override HTTP status to 403
	statusCode := http.StatusForbidden
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(NewJSONErrorResponse(accessDeniedError))
		return
	}
	s.renderHTTPError(w, statusCode, "Access Denied", accessDeniedError.Message)
}

// renderAppError renders an AppError as JSON for API endpoints or HTML for others.
// API endpoints are detected by the /saml/api/ path prefix.
func (s *SAMLDisco) renderAppError(w http.ResponseWriter, r *http.Request, err *domain.AppError) {
	statusCode := HTTPStatusForCode(err.Code)

	// API endpoints get JSON responses
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(NewJSONErrorResponse(err))
		return
	}

	// Non-API endpoints get HTML
	s.renderHTTPError(w, statusCode, TitleForCode(err.Code), err.Message)
}

// handleDeniedForSP handles access denied responses for a specific SP config.
func (s *SAMLDisco) handleDeniedForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, subject string) {
	redirect := ValidateDenyRedirect(spConfig.EntitlementDenyRedirect)
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	// Default 403 with error page
	accessDeniedError := &domain.AppError{
		Code:    domain.ErrCodeBadRequest,
		Message: "Access denied by entitlements policy",
		Cause:   domain.ErrAccessDenied,
	}
	statusCode := http.StatusForbidden
	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(NewJSONErrorResponse(accessDeniedError))
		return
	}
	s.renderHTTPError(w, statusCode, "Access Denied", accessDeniedError.Message)
}

// renderDiscoveryHTMLForSP renders the discovery UI HTML for a specific SP config.
func (s *SAMLDisco) renderDiscoveryHTMLForSP(w http.ResponseWriter, r *http.Request, spConfig *SPConfig, idps []domain.IdPInfo, returnURL string) error {
	// Localize IdPs based on Accept-Language header
	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	defaultLang := s.getDefaultLanguage()
	if spConfig.DefaultLanguage != "" {
		defaultLang = spConfig.DefaultLanguage
	}
	localizedIdPs := localizeIdPList(idps, langPrefs, defaultLang)

	// Separate pinned IdPs from the main list
	pinnedIdPs, filteredIdPs := s.separatePinnedIdPsForSP(spConfig, localizedIdPs)

	// Append guest access entry to pinned IdPs if configured
	if spConfig.GuestAccessLabel != "" {
		pinnedIdPs = append(pinnedIdPs, domain.IdPInfo{
			EntityID:    GuestEntityID,
			DisplayName: spConfig.GuestAccessLabel,
		})
	}

	// Get the remembered IdP entity ID
	rememberedIdPID := s.getRememberIdPCookieForSP(r, spConfig)

	// Look up full IdP info for the remembered IdP (and localize it)
	var rememberedIdP *domain.IdPInfo
	if rememberedIdPID != "" && spConfig.metadataStore != nil {
		if idp, err := spConfig.metadataStore.GetIdP(rememberedIdPID); err == nil {
			localized := domain.LocalizeIdPInfo(*idp, langPrefs, defaultLang)
			rememberedIdP = &localized
		}
	}

	// Convert alt login config to template data
	altLogins := make([]AltLoginOption, len(spConfig.AltLogins))
	for i, alt := range spConfig.AltLogins {
		altLogins[i] = AltLoginOption{URL: alt.URL, Label: alt.Label}
	}

	renderer := spConfig.templateRenderer
	if renderer == nil {
		renderer = s.templateRenderer
	}
	if renderer == nil {
		return fmt.Errorf("template renderer not configured")
	}

	return renderer.RenderDisco(w, DiscoData{
		IdPs:            filteredIdPs,
		PinnedIdPs:      pinnedIdPs,
		ReturnURL:       returnURL,
		RememberedIdPID: rememberedIdPID,
		RememberedIdP:   rememberedIdP,
		AltLogins:       altLogins,
		ServiceName:     spConfig.ServiceName,
	})
}
