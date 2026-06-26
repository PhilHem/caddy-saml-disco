package caddy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

type sessionExpiredJSONResponse struct {
	Error    string `json:"error"`
	LoginURL string `json:"login_url"`
}

func (s *SAMLDisco) answerSessionExpiredJSON(w http.ResponseWriter, r *http.Request, spConfig *SPConfig) bool {
	if !wantsJSONAuthFailure(r) {
		return false
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-SAML-Session-Expired", "1")
	if spConfig != nil {
		httputil.ClearSessionCookieWithConfig(w, r, &spCookieConfig{sp: spConfig})
	}
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(sessionExpiredJSONResponse{
		Error:    "session_expired",
		LoginURL: sessionExpiredLoginURL(r),
	})
	return true
}

func wantsJSONAuthFailure(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		return true
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		return true
	}

	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}

	fetchMode := strings.ToLower(r.Header.Get("Sec-Fetch-Mode"))
	return fetchMode != "" && fetchMode != "navigate"
}

func sessionExpiredLoginURL(r *http.Request) string {
	return "/saml/disco?return_url=" + url.QueryEscape(sessionExpiredReturnURL(r))
}

func sessionExpiredReturnURL(r *http.Request) string {
	if ref := r.Header.Get("Referer"); ref != "" {
		if returnURL := sameHostRelativeURL(ref, r.Host); returnURL != "" {
			return returnURL
		}
	}
	return "/"
}

func sameHostRelativeURL(rawURL, host string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host != host || parsed.Path == "" || strings.HasPrefix(parsed.Path, "/saml/") {
		return ""
	}

	relative := parsed.RequestURI()
	if parsed.Fragment != "" {
		relative += "#" + parsed.Fragment
	}
	return httputil.ValidateRelayState(relative)
}
