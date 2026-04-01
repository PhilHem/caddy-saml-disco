//go:build unit

package session

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"testing/quick"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// generateTestKey generates a test RSA key pair.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

// TestCookieSessionStore_Interface verifies the interface contract.
func TestCookieSessionStore_Interface(t *testing.T) {
	var _ ports.SessionStore = (*CookieSessionStore)(nil)
}

// TestCookieSessionStore_Create_ValidToken verifies Create returns a valid JWT token.
func TestCookieSessionStore_Create_ValidToken(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	session := &domain.Session{
		Subject:      "user@example.com",
		IdPEntityID:  "https://idp.example.com",
		Attributes:   map[string]string{"email": "user@example.com"},
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SessionIndex: "_session_123",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}
	if token == "" {
		t.Error("Create() returned empty token")
	}

	// Token should be a valid JWT (3 parts separated by dots)
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected JWT with 2 dots, got %d", parts)
	}
}

// TestCookieSessionStore_Get_Valid verifies Get returns the original session data.
func TestCookieSessionStore_Get_Valid(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	original := &domain.Session{
		Subject:      "user@example.com",
		IdPEntityID:  "https://idp.example.com",
		Attributes:   map[string]string{"email": "user@example.com", "role": "admin"},
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SessionIndex: "_session_123",
	}

	token, err := store.Create(original)
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	retrieved, err := store.Get(token)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}

	if retrieved.Subject != original.Subject {
		t.Errorf("Subject = %q, want %q", retrieved.Subject, original.Subject)
	}
	if retrieved.IdPEntityID != original.IdPEntityID {
		t.Errorf("IdPEntityID = %q, want %q", retrieved.IdPEntityID, original.IdPEntityID)
	}
	if retrieved.NameIDFormat != original.NameIDFormat {
		t.Errorf("NameIDFormat = %q, want %q", retrieved.NameIDFormat, original.NameIDFormat)
	}
	if retrieved.SessionIndex != original.SessionIndex {
		t.Errorf("SessionIndex = %q, want %q", retrieved.SessionIndex, original.SessionIndex)
	}
	if len(retrieved.Attributes) != len(original.Attributes) {
		t.Errorf("Attributes length = %d, want %d", len(retrieved.Attributes), len(original.Attributes))
	}
	for k, v := range original.Attributes {
		if retrieved.Attributes[k] != v {
			t.Errorf("Attributes[%q] = %q, want %q", k, retrieved.Attributes[k], v)
		}
	}
}

// TestCookieSessionStore_Get_Expired verifies Get returns error for expired tokens.
func TestCookieSessionStore_Get_Expired(t *testing.T) {
	key := generateTestKey(t)
	// Create store with very short duration
	store := NewCookieSessionStore(key, 10*time.Millisecond)

	session := &domain.Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	// Wait for token to expire
	time.Sleep(20 * time.Millisecond)

	_, err = store.Get(token)
	if err == nil {
		t.Error("Get() should return error for expired token")
	}
	if err != ports.ErrSessionNotFound {
		t.Errorf("Get() error = %v, want %v", err, ports.ErrSessionNotFound)
	}
}

// TestCookieSessionStore_Get_InvalidToken verifies Get returns error for invalid tokens.
func TestCookieSessionStore_Get_InvalidToken(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt-token"},
		{"malformed", "header.payload"},
		{"wrong-signature", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.invalid"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Get(tc.token)
			if err == nil {
				t.Error("Get() should return error for invalid token")
			}
			if err != ports.ErrSessionNotFound {
				t.Errorf("Get() error = %v, want %v", err, ports.ErrSessionNotFound)
			}
		})
	}
}

// TestCookieSessionStore_Delete_NoOp verifies Delete is a no-op for stateless JWT.
func TestCookieSessionStore_Delete_NoOp(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	session := &domain.Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	// Delete should return nil (no-op)
	if err := store.Delete(token); err != nil {
		t.Errorf("Delete() returned error: %v", err)
	}

	// Token should still be valid after delete (stateless)
	if _, err := store.Get(token); err != nil {
		t.Errorf("Get() after Delete() returned error: %v", err)
	}
}

// TestCookieSessionStore_Concurrency_ThreadSafe verifies thread-safety.
func TestCookieSessionStore_Concurrency_ThreadSafe(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	const numGoroutines = 100
	const numOpsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numOpsPerGoroutine*2)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				session := &domain.Session{
					Subject:     "user@example.com",
					IdPEntityID: "https://idp.example.com",
					Attributes:  map[string]string{"id": "value"},
				}

				token, err := store.Create(session)
				if err != nil {
					errors <- err
					continue
				}

				_, err = store.Get(token)
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	var errCount int
	for err := range errors {
		t.Errorf("concurrent operation error: %v", err)
		errCount++
	}
	if errCount > 0 {
		t.Fatalf("had %d errors in concurrent operations", errCount)
	}
}

// TestCookieSessionStore_Property_TokenUniqueness verifies tokens with different data are unique.
func TestCookieSessionStore_Property_TokenUniqueness(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	f := func(subject1, subject2 string) bool {
		// Skip if subjects are the same or empty
		if subject1 == subject2 || subject1 == "" || subject2 == "" {
			return true
		}

		session1 := &domain.Session{
			Subject:     subject1,
			IdPEntityID: "https://idp.example.com",
		}
		session2 := &domain.Session{
			Subject:     subject2,
			IdPEntityID: "https://idp.example.com",
		}

		token1, err1 := store.Create(session1)
		token2, err2 := store.Create(session2)

		if err1 != nil || err2 != nil {
			return false
		}

		// Tokens with different subjects should be different
		return token1 != token2
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Error(err)
	}
}

// TestCookieSessionStore_Property_Roundtrip verifies session data survives roundtrip.
func TestCookieSessionStore_Property_Roundtrip(t *testing.T) {
	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	f := func(subject, idpEntityID, nameIDFormat, sessionIndex string) bool {
		// Skip empty subjects (JWT requires subject)
		if subject == "" {
			return true
		}

		original := &domain.Session{
			Subject:      subject,
			IdPEntityID:  idpEntityID,
			NameIDFormat: nameIDFormat,
			SessionIndex: sessionIndex,
			Attributes:   map[string]string{},
		}

		token, err := store.Create(original)
		if err != nil {
			return false
		}

		retrieved, err := store.Get(token)
		if err != nil {
			return false
		}

		return retrieved.Subject == original.Subject &&
			retrieved.IdPEntityID == original.IdPEntityID &&
			retrieved.NameIDFormat == original.NameIDFormat &&
			retrieved.SessionIndex == original.SessionIndex
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// TestCookieSessionStore_Version_Roundtrip verifies that a token created with the
// current schema version can be decoded successfully.
func TestCookieSessionStore_Version_Roundtrip(t *testing.T) {
	tra.RequireLegacy(t)

	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	session := &domain.Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
	}

	token, err := store.Create(session)
	if err != nil {
		t.Fatalf("Create() returned error: %v", err)
	}

	retrieved, err := store.Get(token)
	if err != nil {
		t.Fatalf("Get() returned error for current-version token: %v", err)
	}
	if retrieved.Subject != session.Subject {
		t.Errorf("Subject = %q, want %q", retrieved.Subject, session.Subject)
	}
}

// TestCookieSessionStore_Version_MissingRejectsToken verifies that a JWT without a
// "ver" claim (e.g. produced by an older binary) is rejected with ErrSessionNotFound.
func TestCookieSessionStore_Version_MissingRejectsToken(t *testing.T) {
	tra.RequireLegacy(t)

	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	// Craft a token using a claims struct that has no ver field, mimicking an old binary.
	type legacyClaims struct {
		jwt.RegisteredClaims
		IdPEntityID string `json:"idp"`
	}

	now := time.Now()
	claims := legacyClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user@example.com",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		IdPEntityID: "https://idp.example.com",
	}

	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign legacy token: %v", err)
	}

	_, err = store.Get(raw)
	if err == nil {
		t.Fatal("Get() should reject token with missing ver claim")
	}
	if err != ports.ErrSessionNotFound {
		t.Errorf("Get() error = %v, want %v", err, ports.ErrSessionNotFound)
	}
}

// TestCookieSessionStore_Version_WrongVersionRejectsToken verifies that a JWT with a
// ver claim that doesn't match currentSessionVersion is rejected.
func TestCookieSessionStore_Version_WrongVersionRejectsToken(t *testing.T) {
	tra.RequireLegacy(t)

	key := generateTestKey(t)
	store := NewCookieSessionStore(key, time.Hour)

	// Craft a token with a future/unknown version number.
	type futureVersionClaims struct {
		jwt.RegisteredClaims
		Version     int    `json:"ver"`
		IdPEntityID string `json:"idp"`
	}

	now := time.Now()
	claims := futureVersionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user@example.com",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Version:     currentSessionVersion + 1,
		IdPEntityID: "https://idp.example.com",
	}

	raw, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign future-version token: %v", err)
	}

	_, err = store.Get(raw)
	if err == nil {
		t.Fatal("Get() should reject token with wrong ver claim")
	}
	if err != ports.ErrSessionNotFound {
		t.Errorf("Get() error = %v, want %v", err, ports.ErrSessionNotFound)
	}
}
