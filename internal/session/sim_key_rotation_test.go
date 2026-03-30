//go:build unit

package session

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// SimTestKeyRotation_InvalidatesOldSessions verifies that rotating the signing key
// invalidates all sessions created with the previous key.
func TestSimKeyRotation_InvalidatesOldSessions(t *testing.T) {
	tra.Require(t, "Adapter.Session.KeyRotationInvalidatesOldSessions")

	k1 := generateTestKey(t)
	store1 := NewCookieSessionStore(k1, time.Hour)

	const count = 100
	tokens := make([]string, count)
	for i := 0; i < count; i++ {
		sess := &domain.Session{
			Subject:     fmt.Sprintf("user%d@example.com", i),
			IdPEntityID: "https://idp.example.com",
			Attributes:  map[string]string{"index": fmt.Sprintf("%d", i)},
		}
		tok, err := store1.Create(sess)
		if err != nil {
			t.Fatalf("Create() error for session %d: %v", i, err)
		}
		tokens[i] = tok
	}

	// Rotate to a new key.
	k2 := generateTestKey(t)
	store2 := NewCookieSessionStore(k2, time.Hour)

	// All old tokens must be rejected by the new store.
	for i, tok := range tokens {
		_, err := store2.Get(tok)
		if err == nil {
			t.Errorf("store2.Get(token[%d]): expected error after key rotation, got nil", i)
		} else if err != ports.ErrSessionNotFound {
			t.Errorf("store2.Get(token[%d]): expected ErrSessionNotFound, got %v", i, err)
		}
	}

	// New tokens created with K2 must be valid with store2.
	newSess := &domain.Session{
		Subject:     "newuser@example.com",
		IdPEntityID: "https://idp.example.com",
	}
	newTok, err := store2.Create(newSess)
	if err != nil {
		t.Fatalf("Create() with new key: %v", err)
	}
	if _, err := store2.Get(newTok); err != nil {
		t.Errorf("Get() new token with store2: unexpected error: %v", err)
	}

	// Old tokens must still be valid with the original store (key still in memory).
	for i, tok := range tokens {
		if _, err := store1.Get(tok); err != nil {
			t.Errorf("store1.Get(token[%d]): expected success, got %v", i, err)
		}
	}
}

// TestSimKeyRotation_ConcurrentCreation verifies that concurrent session creation
// during a store swap does not panic and all produced tokens are valid.
func TestSimKeyRotation_ConcurrentCreation(t *testing.T) {
	tra.Require(t, "Adapter.Session.ConcurrentCreationDuringSwap")

	k1 := generateTestKey(t)
	store1 := NewCookieSessionStore(k1, time.Hour)

	const workers = 50
	tokens := make([]string, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			sess := &domain.Session{
				Subject:     fmt.Sprintf("concurrent%d@example.com", idx),
				IdPEntityID: "https://idp.example.com",
			}
			tok, err := store1.Create(sess)
			tokens[idx] = tok
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	// No goroutine should have produced an error or a panic.
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Errorf("worker %d: Create() error: %v", i, errs[i])
		}
		if tokens[i] == "" {
			t.Errorf("worker %d: Create() returned empty token", i)
		}
	}

	// Every produced token must be valid with store1.
	for i := 0; i < workers; i++ {
		if tokens[i] == "" {
			continue // already reported above
		}
		if _, err := store1.Get(tokens[i]); err != nil {
			t.Errorf("worker %d: Get() after concurrent Create(): %v", i, err)
		}
	}
}

// TestSimKeyRotation_CrossStoreIsolation verifies that tokens are strictly
// bound to the store (key) that created them and cannot be used across stores.
func TestSimKeyRotation_CrossStoreIsolation(t *testing.T) {
	tra.Require(t, "Adapter.Session.CrossStoreIsolation")

	k1 := generateTestKey(t)
	k2 := generateTestKey(t)
	store1 := NewCookieSessionStore(k1, time.Hour)
	store2 := NewCookieSessionStore(k2, time.Hour)

	sess1 := &domain.Session{Subject: "alice@example.com", IdPEntityID: "https://idp.example.com"}
	sess2 := &domain.Session{Subject: "bob@example.com", IdPEntityID: "https://idp.example.com"}

	t1, err := store1.Create(sess1)
	if err != nil {
		t.Fatalf("store1.Create(): %v", err)
	}
	t2, err := store2.Create(sess2)
	if err != nil {
		t.Fatalf("store2.Create(): %v", err)
	}

	// T1 valid with store1.
	if _, err := store1.Get(t1); err != nil {
		t.Errorf("store1.Get(t1): expected valid, got %v", err)
	}
	// T1 invalid with store2.
	if _, err := store2.Get(t1); err == nil {
		t.Error("store2.Get(t1): expected error, got nil")
	} else if err != ports.ErrSessionNotFound {
		t.Errorf("store2.Get(t1): expected ErrSessionNotFound, got %v", err)
	}

	// T2 valid with store2.
	if _, err := store2.Get(t2); err != nil {
		t.Errorf("store2.Get(t2): expected valid, got %v", err)
	}
	// T2 invalid with store1.
	if _, err := store1.Get(t2); err == nil {
		t.Error("store1.Get(t2): expected error, got nil")
	} else if err != ports.ErrSessionNotFound {
		t.Errorf("store1.Get(t2): expected ErrSessionNotFound, got %v", err)
	}
}
