package caddysamldisco

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Session holds authenticated user information.
// This is the core domain model - it has no external dependencies.
type Session struct {
	// Subject is the SAML NameID (user identifier).
	Subject string

	// Attributes contains SAML attributes from the assertion.
	Attributes map[string]string

	// IdPEntityID identifies which IdP authenticated the user.
	IdPEntityID string

	// IssuedAt is when the session was created.
	IssuedAt time.Time

	// ExpiresAt is when the session expires.
	ExpiresAt time.Time
}

// SessionStore is the port interface for session management.
type SessionStore interface {
	// Create creates a new session and returns a token.
	Create(session *Session) (string, error)

	// Get retrieves a session by token. Returns ErrSessionNotFound if
	// the token is invalid, expired, or not found.
	Get(token string) (*Session, error)

	// Delete removes a session. For stateless implementations (JWT),
	// this may be a no-op as actual cookie removal happens in HTTP layer.
	Delete(token string) error
}

// ErrSessionNotFound is returned when a session cannot be found or is invalid.
var ErrSessionNotFound = errors.New("session not found")

// CookieSessionStore implements SessionStore using JWT tokens.
// Tokens are signed with RSA (RS256) and are stateless.
type CookieSessionStore struct {
	privateKey *rsa.PrivateKey
	duration   time.Duration
}

// sessionClaims defines the JWT claims structure for sessions.
type sessionClaims struct {
	jwt.RegisteredClaims
	IdPEntityID string            `json:"idp"`
	Attributes  map[string]string `json:"attrs,omitempty"`
}

// NewCookieSessionStore creates a new JWT-based session store.
func NewCookieSessionStore(privateKey *rsa.PrivateKey, duration time.Duration) *CookieSessionStore {
	return &CookieSessionStore{
		privateKey: privateKey,
		duration:   duration,
	}
}

// Create generates a signed JWT token from the session.
func (s *CookieSessionStore) Create(session *Session) (string, error) {
	now := time.Now()
	claims := sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   session.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.duration)),
		},
		IdPEntityID: session.IdPEntityID,
		Attributes:  session.Attributes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// Get validates a JWT token and returns the session.
func (s *CookieSessionStore) Get(token string) (*Session, error) {
	parsed, err := jwt.ParseWithClaims(token, &sessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return &s.privateKey.PublicKey, nil
	})
	if err != nil {
		return nil, ErrSessionNotFound
	}

	claims, ok := parsed.Claims.(*sessionClaims)
	if !ok || !parsed.Valid {
		return nil, ErrSessionNotFound
	}

	return &Session{
		Subject:     claims.Subject,
		Attributes:  claims.Attributes,
		IdPEntityID: claims.IdPEntityID,
		IssuedAt:    claims.IssuedAt.Time,
		ExpiresAt:   claims.ExpiresAt.Time,
	}, nil
}

// Delete is a no-op for stateless JWT sessions.
// Actual cookie removal happens in the HTTP layer.
func (s *CookieSessionStore) Delete(token string) error {
	return nil
}

// LoadPrivateKey loads an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try PKCS8 first (modern format), then PKCS1 (legacy RSA format)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return rsaKey, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}

	return rsaKey, nil
}
