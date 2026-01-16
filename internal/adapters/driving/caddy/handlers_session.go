package caddy

import (
	"encoding/json"
	"net/http"
)

// handlers_session.go - Session info handler

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
