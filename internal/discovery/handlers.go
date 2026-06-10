package discovery

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

// idpListResponse is the JSON response for GET /saml/api/idps.
type idpListResponse struct {
	IdPs          []domain.IdPInfo `json:"idps"`
	PinnedIdPs    []domain.IdPInfo `json:"pinned_idps,omitempty"`
	RememberedIdP string           `json:"remembered_idp_id,omitempty"`
}

// selectIdPRequest is the JSON request body for POST /saml/api/select.
type selectIdPRequest struct {
	EntityID  string `json:"entity_id"`
	ReturnURL string `json:"return_url"`
	Remember  bool   `json:"remember"`
	Passcode  string `json:"passcode,omitempty"`
}

// HandleListIdPs handles GET /saml/api/idps.
func (h *DiscoveryHandler) HandleListIdPs(w http.ResponseWriter, r *http.Request) error {
	if h.MetadataStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	filter := r.URL.Query().Get("q")

	idps, err := h.MetadataStore.ListIdPs(filter)
	if err != nil {
		h.renderAppError(w, r, domain.ServiceError("Failed to list identity providers"))
		return err
	}

	if idps == nil {
		idps = []domain.IdPInfo{}
	}

	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	defaultLang := h.defaultLanguage()
	idps = localizeIdPList(idps, langPrefs, defaultLang)

	pinnedIdPs, filteredIdPs := domain.SeparatePinnedIdPs(idps, h.Config.PinnedIdPs)

	if h.Config.GuestAccessLabel != "" {
		filteredIdPs = append(filteredIdPs, domain.IdPInfo{
			EntityID:    GuestEntityID,
			DisplayName: h.Config.GuestAccessLabel,
		})
	}

	if len(filteredIdPs) == 0 && len(idps) > 0 {
		h.getLogger().Warn("empty IdP list after filtering",
			zap.Int("total_idps", len(idps)),
			zap.Int("pinned_idps", len(pinnedIdPs)),
			zap.String("filter", filter),
		)
	}

	response := idpListResponse{
		IdPs:          filteredIdPs,
		PinnedIdPs:    pinnedIdPs,
		RememberedIdP: h.getRememberIdPCookie(r),
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

// HandleSelectIdP handles POST /saml/api/select.
func (h *DiscoveryHandler) HandleSelectIdP(w http.ResponseWriter, r *http.Request) error {
	var req selectIdPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.renderAppError(w, r, domain.BadRequestError("Request body is invalid"))
		return nil
	}

	if req.EntityID == "" {
		h.renderAppError(w, r, domain.BadRequestError("entity_id is required"))
		return nil
	}

	if req.EntityID == GuestEntityID && h.Config.GuestAccessLabel != "" {
		return h.handleGuestAccess(w, r, req.ReturnURL, req.Passcode)
	}

	if h.MetadataStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idp, err := h.MetadataStore.GetIdP(req.EntityID)
	if err != nil {
		h.getLogger().Debug("idp not found",
			zap.String("entity_id", req.EntityID),
			zap.Error(err),
		)
		h.renderAppError(w, r, domain.IdPNotFoundError(req.EntityID))
		return nil
	}

	h.getLogger().Info("idp selected for authentication",
		zap.String("entity_id", req.EntityID),
	)

	if req.Remember {
		h.setRememberIdPCookie(w, r, req.EntityID)
	}

	if h.isBypassIdP(req.EntityID) {
		return h.handleBypassIdP(w, r, idp, req.ReturnURL, req.Passcode)
	}

	if h.SAMLService == nil {
		h.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return nil
	}

	relayState := req.ReturnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	opts := &domain.AuthnOptions{
		ForceAuthn: h.Config.ForceAuthn || MatchesForceAuthnPath(relayState, h.Config.ForceAuthnPaths),
	}

	acsURL := h.resolveAcsURL(r)
	redirectURL, err := h.SAMLService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		h.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": redirectURL.String(),
	}); err != nil {
		h.getLogger().Warn("failed to encode select response", zap.Error(err))
	}
	return nil
}

// HandleDiscoveryUI handles GET /saml/disco.
func (h *DiscoveryHandler) HandleDiscoveryUI(w http.ResponseWriter, r *http.Request) error {
	if h.MetadataStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return nil
	}

	idps, err := h.MetadataStore.ListIdPs("")
	if err != nil {
		h.renderAppError(w, r, domain.ServiceError("Failed to retrieve identity providers"))
		return nil
	}

	returnURL := ValidateRelayState(r.URL.Query().Get("return_url"))

	// Auto-redirect if only one IdP
	if len(idps) == 1 {
		idp := &idps[0]

		// A configured passcode gates the bypass path. A plain page navigation
		// carries no passcode, so fall through to the discovery page where the
		// user can pick the entry and supply it — never silently bypass.
		if h.isBypassIdP(idp.EntityID) && h.effectivePasscode(idp.EntityID) == "" {
			return h.handleBypassIdP(w, r, idp, returnURL, "")
		}

		if h.isBypassIdP(idp.EntityID) {
			// Passcode-gated bypass: render the discovery page instead.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			return h.renderDiscoveryHTML(w, r, idps, returnURL)
		}

		if h.SAMLService != nil {
			acsURL := h.resolveAcsURL(r)

			opts := &domain.AuthnOptions{
				ForceAuthn: h.Config.ForceAuthn || MatchesForceAuthnPath(returnURL, h.Config.ForceAuthnPaths),
			}

			redirectURL, err := h.SAMLService.StartAuthWithOptions(idp, acsURL, returnURL, opts)
			if err != nil {
				h.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
				return nil
			}
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return nil
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return h.renderDiscoveryHTML(w, r, idps, returnURL)
}

// HandleRedirectToIdP handles unauthenticated requests to protected routes.
// If LoginRedirect is set it redirects there; otherwise it picks an IdP or shows the discovery UI.
func (h *DiscoveryHandler) HandleRedirectToIdP(w http.ResponseWriter, r *http.Request) {
	if h.Config.LoginRedirect != "" {
		redirectURL := h.Config.LoginRedirect
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if h.MetadataStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Metadata store is not configured"))
		return
	}

	idps, err := h.MetadataStore.ListIdPs("")
	if err != nil || len(idps) == 0 {
		h.renderAppError(w, r, domain.ConfigError("No identity provider is configured"))
		return
	}

	if len(idps) > 1 {
		redirectURL := "/saml/disco?return_url=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	idp := &idps[0]

	if h.isBypassIdP(idp.EntityID) {
		// A configured passcode gates the bypass path. This redirect-to-IdP flow
		// has no passcode available, so render the discovery page (where the user
		// can supply it) instead of silently minting a bypass session.
		if h.effectivePasscode(idp.EntityID) != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			h.renderDiscoveryHTML(w, r, idps, ValidateRelayState(r.URL.RequestURI())) //nolint:errcheck
			return
		}
		h.handleBypassIdP(w, r, idp, r.URL.RequestURI(), "") //nolint:errcheck
		return
	}

	if h.SAMLService == nil {
		h.renderAppError(w, r, domain.ConfigError("SAML service is not configured"))
		return
	}

	acsURL := h.resolveAcsURL(r)
	relayState := r.URL.RequestURI()

	opts := &domain.AuthnOptions{
		ForceAuthn: h.Config.ForceAuthn || MatchesForceAuthnPath(r.URL.Path, h.Config.ForceAuthnPaths),
	}

	redirectURL, err := h.SAMLService.StartAuthWithOptions(idp, acsURL, relayState, opts)
	if err != nil {
		h.renderAppError(w, r, domain.AuthError("Failed to start authentication", err))
		return
	}

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// isBypassIdP checks if the given entity ID is configured as a bypass IdP.
func (h *DiscoveryHandler) isBypassIdP(entityID string) bool {
	for _, id := range h.Config.BypassIdPs {
		if id == entityID {
			return true
		}
	}
	return false
}

// effectivePasscode returns the passcode that gates the given no-authentication
// target: a per-target value (keyed by entity ID, with GuestEntityID keying the
// guest_access entry) if one is configured, otherwise the shared GuestPasscode.
// An empty result means the target is ungated.
func (h *DiscoveryHandler) effectivePasscode(entityID string) string {
	if pc, ok := h.Config.GuestPasscodes[entityID]; ok {
		return pc
	}
	return h.Config.GuestPasscode
}

// passcodeMatches reports whether the supplied passcode matches the expected one,
// using a constant-time comparison to avoid leaking length or content through
// timing. It never logs the passcode.
func (h *DiscoveryHandler) passcodeMatches(expected, supplied string) bool {
	if len(supplied) != len(expected) {
		// ConstantTimeCompare already returns 0 on length mismatch, but it is
		// not constant-time across differing lengths; the early return keeps the
		// contract explicit. The brief length-leak here is not security-relevant.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(expected)) == 1
}

// writeInvalidPasscode writes the 401 response the discovery frontend branches on.
func (h *DiscoveryHandler) writeInvalidPasscode(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error": "invalid_passcode",
	}); err != nil {
		h.getLogger().Warn("failed to encode invalid_passcode response", zap.Error(err))
	}
	return nil
}

// handleBypassIdP creates a guest session for a bypass IdP without SAML authentication.
// When a guest passcode is configured, the supplied passcode must match first.
func (h *DiscoveryHandler) handleBypassIdP(w http.ResponseWriter, r *http.Request, idp *domain.IdPInfo, returnURL, passcode string) error {
	if expected := h.effectivePasscode(idp.EntityID); expected != "" && !h.passcodeMatches(expected, passcode) {
		h.getLogger().Info("bypass idp rejected: invalid passcode",
			zap.String("entity_id", idp.EntityID),
		)
		return h.writeInvalidPasscode(w)
	}

	h.getLogger().Info("bypass idp selected, creating guest session",
		zap.String("entity_id", idp.EntityID),
	)

	relayState := returnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	session := &domain.Session{
		Subject:     "guest",
		IdPEntityID: idp.EntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(h.Config.SessionDuration),
	}

	if h.SessionStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Session store is not configured"))
		return nil
	}
	token, err := h.SessionStore.Create(session)
	if err != nil {
		h.renderAppError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}

	h.setSessionCookie(w, r, token)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": relayState,
	}); err != nil {
		h.getLogger().Warn("failed to encode bypass response", zap.Error(err))
	}
	return nil
}

// handleGuestAccess creates a guest session without any SAML authentication.
// When a guest passcode is configured, the supplied passcode must match first.
func (h *DiscoveryHandler) handleGuestAccess(w http.ResponseWriter, r *http.Request, returnURL, passcode string) error {
	if expected := h.effectivePasscode(GuestEntityID); expected != "" && !h.passcodeMatches(expected, passcode) {
		h.getLogger().Info("guest access rejected: invalid passcode")
		return h.writeInvalidPasscode(w)
	}

	h.getLogger().Info("guest access selected, creating guest session")

	relayState := returnURL
	if relayState == "" {
		relayState = "/"
	}
	relayState = ValidateRelayState(relayState)

	session := &domain.Session{
		Subject:     "guest",
		IdPEntityID: GuestEntityID,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(h.Config.SessionDuration),
	}

	if h.SessionStore == nil {
		h.renderAppError(w, r, domain.ConfigError("Session store is not configured"))
		return nil
	}
	token, err := h.SessionStore.Create(session)
	if err != nil {
		h.renderAppError(w, r, domain.ServiceError("Failed to create session"))
		return err
	}

	h.setSessionCookie(w, r, token)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"redirect_url": relayState,
	}); err != nil {
		h.getLogger().Warn("failed to encode guest access response", zap.Error(err))
	}
	return nil
}

// renderDiscoveryHTML renders the discovery UI HTML page.
func (h *DiscoveryHandler) renderDiscoveryHTML(w http.ResponseWriter, r *http.Request, idps []domain.IdPInfo, returnURL string) error {
	if h.Renderer == nil {
		return fmt.Errorf("template renderer not configured")
	}

	langPrefs := ParseAcceptLanguage(r.Header.Get("Accept-Language"))
	defaultLang := h.defaultLanguage()
	localizedIdPs := localizeIdPList(idps, langPrefs, defaultLang)

	pinnedIdPs, filteredIdPs := domain.SeparatePinnedIdPs(localizedIdPs, h.Config.PinnedIdPs)

	if h.Config.GuestAccessLabel != "" {
		filteredIdPs = append(filteredIdPs, domain.IdPInfo{
			EntityID:    GuestEntityID,
			DisplayName: h.Config.GuestAccessLabel,
		})
	}

	rememberedIdPID := h.getRememberIdPCookie(r)

	var rememberedIdP *domain.IdPInfo
	if rememberedIdPID != "" && h.MetadataStore != nil {
		if idp, err := h.MetadataStore.GetIdP(rememberedIdPID); err == nil {
			localized := domain.LocalizeIdPInfo(*idp, langPrefs, defaultLang)
			rememberedIdP = &localized
		}
	}

	altLogins := make([]AltLoginOption, len(h.Config.AltLogins))
	for i, alt := range h.Config.AltLogins {
		altLogins[i] = AltLoginOption(alt)
	}

	data := DiscoData{
		IdPs:            filteredIdPs,
		PinnedIdPs:      pinnedIdPs,
		ReturnURL:       returnURL,
		RememberedIdPID: rememberedIdPID,
		RememberedIdP:   rememberedIdP,
		AltLogins:       altLogins,
		ServiceName:     h.Config.ServiceName,
	}

	// Tell the page which entries gate on a passcode, evaluated per target so a
	// guest_access and each bypass_idp can carry distinct codes (or none): the
	// guest sentinel (if guest_access is set) and every bypass IdP with a
	// non-empty effective passcode.
	if h.Config.GuestAccessLabel != "" && h.effectivePasscode(GuestEntityID) != "" {
		data.PasscodeRequired = true
		data.PasscodeRequiredEntityIDs = append(data.PasscodeRequiredEntityIDs, GuestEntityID)
	}
	for _, id := range h.Config.BypassIdPs {
		if h.effectivePasscode(id) != "" {
			data.PasscodeRequired = true
			data.PasscodeRequiredEntityIDs = append(data.PasscodeRequiredEntityIDs, id)
		}
	}

	return h.Renderer.RenderDisco(w, data)
}

// renderAppError renders an AppError as JSON (for API endpoints) or HTML (for UI endpoints).
func (h *DiscoveryHandler) renderAppError(w http.ResponseWriter, r *http.Request, err *domain.AppError) {
	statusCode := httputil.HTTPStatusForCode(err.Code)

	if strings.HasPrefix(r.URL.Path, "/saml/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if encErr := json.NewEncoder(w).Encode(httputil.NewJSONErrorResponse(err)); encErr != nil {
			h.getLogger().Warn("failed to encode error response", zap.Error(encErr))
		}
		return
	}

	h.renderHTTPError(w, statusCode, httputil.TitleForCode(err.Code), err.Message)
}

// renderHTTPError renders an HTML error page with the given status code.
func (h *DiscoveryHandler) renderHTTPError(w http.ResponseWriter, statusCode int, title, message string) {
	if h.Renderer == nil {
		http.Error(w, message, statusCode)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := h.Renderer.RenderError(w, ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		h.getLogger().Warn("failed to render error page", zap.Error(err))
	}
}

// defaultLanguage returns the configured default language, falling back to "en".
func (h *DiscoveryHandler) defaultLanguage() string {
	if h.Config.DefaultLanguage != "" {
		return h.Config.DefaultLanguage
	}
	return "en"
}
