package caddy

import (
	"encoding/json"
	"net/http"
)

type sessionInfoResponse struct {
	Authenticated bool              `json:"authenticated"`
	Subject       string            `json:"subject,omitempty"`
	IdPEntityID   string            `json:"idp_entity_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

func (s *SAMLDisco) handleSessionInfoInternal(w http.ResponseWriter, r *http.Request, cfg *SPConfig) error {
	response := sessionInfoResponse{Authenticated: false}
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
