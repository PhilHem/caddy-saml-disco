package ports

import (
	"errors"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// SessionStore is the port interface for session management.
type SessionStore interface {
	// Create creates a new session and returns a token.
	Create(session *domain.Session) (string, error)

	// Get retrieves a session by token. Returns ErrSessionNotFound if
	// the token is invalid, expired, or not found.
	Get(token string) (*domain.Session, error)

	// Delete removes a session. For stateless implementations (JWT),
	// this may be a no-op as actual cookie removal happens in HTTP layer.
	Delete(token string) error
}

// ErrSessionNotFound is returned when a session cannot be found or is invalid.
var ErrSessionNotFound = errors.New("session not found")
