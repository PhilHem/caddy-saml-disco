//go:build unit

package caddysamldisco

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSession_Fields verifies the Session struct has all required fields.
func TestSession_Fields(t *testing.T) {
	now := time.Now()
	session := Session{
		Subject:     "user@example.com",
		Attributes:  map[string]string{"email": "user@example.com", "name": "Test User"},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    now,
		ExpiresAt:   now.Add(8 * time.Hour),
	}

	if session.Subject != "user@example.com" {
		t.Errorf("Subject = %q, want %q", session.Subject, "user@example.com")
	}
	if session.Attributes["email"] != "user@example.com" {
		t.Errorf("Attributes[email] = %q, want %q", session.Attributes["email"], "user@example.com")
	}
	if session.IdPEntityID != "https://idp.example.com" {
		t.Errorf("IdPEntityID = %q, want %q", session.IdPEntityID, "https://idp.example.com")
	}
	if !session.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt = %v, want %v", session.IssuedAt, now)
	}
	if !session.ExpiresAt.Equal(now.Add(8 * time.Hour)) {
		t.Errorf("ExpiresAt = %v, want %v", session.ExpiresAt, now.Add(8*time.Hour))
	}
}

// TestErrSessionNotFound verifies the sentinel error exists and is usable.
func TestErrSessionNotFound(t *testing.T) {
	if ErrSessionNotFound == nil {
		t.Fatal("ErrSessionNotFound should not be nil")
	}

	// Verify it can be used with errors.Is
	err := ErrSessionNotFound
	if !errors.Is(err, ErrSessionNotFound) {
		t.Error("errors.Is should match ErrSessionNotFound")
	}
}

// TestSessionStore_Interface verifies the SessionStore interface is defined correctly.
func TestSessionStore_Interface(t *testing.T) {
	// This test just verifies the interface exists and has the expected methods.
	// It will fail to compile if the interface is missing or has wrong signatures.
	var _ SessionStore = (*mockSessionStore)(nil)
}

// mockSessionStore is a test double that implements SessionStore.
type mockSessionStore struct{}

func (m *mockSessionStore) Create(session *Session) (string, error) {
	return "mock-token", nil
}

func (m *mockSessionStore) Get(token string) (*Session, error) {
	return nil, ErrSessionNotFound
}

func (m *mockSessionStore) Delete(token string) error {
	return nil
}

// loadTestKey loads the test private key from testdata.
func loadTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	keyPEM, err := os.ReadFile("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("key is not RSA")
	}

	return rsaKey
}

// TestCookieSessionStore_Create verifies that Create returns a JWT token.
func TestCookieSessionStore_Create(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	session := &Session{
		Subject:     "user@example.com",
		Attributes:  map[string]string{"email": "user@example.com"},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	if token == "" {
		t.Error("Create() returned empty token")
	}

	// JWT has 3 parts separated by dots
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("token has %d parts, want 3 (JWT format)", len(parts))
	}
}

// TestCookieSessionStore_Create_ContainsClaims verifies the token contains expected claims.
func TestCookieSessionStore_Create_ContainsClaims(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	now := time.Now()
	session := &Session{
		Subject:     "testuser",
		Attributes:  map[string]string{"role": "admin"},
		IdPEntityID: "https://idp.example.com",
		IssuedAt:    now,
		ExpiresAt:   now.Add(8 * time.Hour),
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Verify we can get the session back (round-trip test)
	retrieved, err := store.Get(token)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved.Subject != session.Subject {
		t.Errorf("Subject = %q, want %q", retrieved.Subject, session.Subject)
	}
	if retrieved.IdPEntityID != session.IdPEntityID {
		t.Errorf("IdPEntityID = %q, want %q", retrieved.IdPEntityID, session.IdPEntityID)
	}
	if retrieved.Attributes["role"] != "admin" {
		t.Errorf("Attributes[role] = %q, want %q", retrieved.Attributes["role"], "admin")
	}
}

// TestCookieSessionStore_Get_ExpiredToken verifies expired tokens return ErrSessionNotFound.
func TestCookieSessionStore_Get_ExpiredToken(t *testing.T) {
	key := loadTestKey(t)
	// Create store with very short duration
	store := NewCookieSessionStore(key, 1*time.Millisecond)

	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err = store.Get(token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Get() error = %v, want ErrSessionNotFound", err)
	}
}

// TestCookieSessionStore_Get_InvalidSignature verifies tampered tokens are rejected.
func TestCookieSessionStore_Get_InvalidSignature(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	session := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Tamper with the token by modifying the signature
	parts := strings.Split(token, ".")
	parts[2] = "tampered-signature"
	tamperedToken := strings.Join(parts, ".")

	_, err = store.Get(tamperedToken)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("Get() error = %v, want ErrSessionNotFound", err)
	}
}

// TestCookieSessionStore_Get_MalformedToken verifies garbage input is rejected.
func TestCookieSessionStore_Get_MalformedToken(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt"},
		{"partial", "header.payload"},
		{"wrong parts", "a.b.c.d"},
	}

	for _, tc := range tests {
		_, err := store.Get(tc.token)
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrSessionNotFound", tc.name, err)
		}
	}
}

// TestCookieSessionStore_Delete verifies Delete returns nil (stateless).
func TestCookieSessionStore_Delete(t *testing.T) {
	key := loadTestKey(t)
	store := NewCookieSessionStore(key, 8*time.Hour)

	err := store.Delete("any-token")
	if err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

// TestCookieSessionStore_ImplementsInterface verifies CookieSessionStore implements SessionStore.
func TestCookieSessionStore_ImplementsInterface(t *testing.T) {
	var _ SessionStore = (*CookieSessionStore)(nil)
}

// TestLoadPrivateKey loads a valid PEM private key file.
func TestLoadPrivateKey(t *testing.T) {
	key, err := LoadPrivateKey("testdata/sp-key.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey() failed: %v", err)
	}

	if key == nil {
		t.Fatal("LoadPrivateKey() returned nil key")
	}

	// Verify it's a valid RSA key by checking the public exponent
	if key.E == 0 {
		t.Error("LoadPrivateKey() returned key with zero public exponent")
	}
}

// TestLoadPrivateKey_FileNotFound returns error for missing file.
func TestLoadPrivateKey_FileNotFound(t *testing.T) {
	_, err := LoadPrivateKey("testdata/nonexistent.pem")
	if err == nil {
		t.Error("LoadPrivateKey() should fail for missing file")
	}
}

// TestLoadPrivateKey_InvalidPEM returns error for invalid PEM.
func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	// Create a temp file with invalid PEM
	dir := t.TempDir()
	path := dir + "/invalid.pem"
	if err := os.WriteFile(path, []byte("not a pem file"), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPrivateKey(path)
	if err == nil {
		t.Error("LoadPrivateKey() should fail for invalid PEM")
	}
}
