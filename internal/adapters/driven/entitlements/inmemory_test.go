//go:build unit

package entitlements

import (
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

func TestInMemoryEntitlementStore_LookupExact(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.Add(domain.Entitlement{
		Subject: "admin@example.edu",
		Roles:   []string{"admin"},
	})

	result, err := store.Lookup("admin@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if !result.Matched {
		t.Error("Lookup() Matched = false, want true")
	}
	if len(result.Roles) != 1 || result.Roles[0] != "admin" {
		t.Errorf("Lookup() Roles = %v, want [admin]", result.Roles)
	}
}

func TestInMemoryEntitlementStore_LookupPattern(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.Add(domain.Entitlement{
		Pattern: "*@example.edu",
		Roles:   []string{"user"},
	})

	result, err := store.Lookup("anyone@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if !result.Matched {
		t.Error("Lookup() Matched = false, want true")
	}
	if len(result.Roles) != 1 || result.Roles[0] != "user" {
		t.Errorf("Lookup() Roles = %v, want [user]", result.Roles)
	}
}

func TestInMemoryEntitlementStore_ExactMatchPrecedence(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.Add(domain.Entitlement{Pattern: "*@example.edu", Roles: []string{"user"}})
	store.Add(domain.Entitlement{Subject: "admin@example.edu", Roles: []string{"admin"}})

	result, err := store.Lookup("admin@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if len(result.Roles) != 1 || result.Roles[0] != "admin" {
		t.Errorf("Lookup() Roles = %v, want [admin] (exact match should take precedence)", result.Roles)
	}
}

func TestInMemoryEntitlementStore_DefaultActionDeny(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.SetDefaultAction(domain.DefaultActionDeny)

	_, err := store.Lookup("unknown@example.edu")
	if err == nil {
		t.Error("Lookup() error = nil, want ErrEntitlementNotFound")
	}
	if err != domain.ErrEntitlementNotFound {
		t.Errorf("Lookup() error = %v, want ErrEntitlementNotFound", err)
	}
}

func TestInMemoryEntitlementStore_DefaultActionAllow(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.SetDefaultAction(domain.DefaultActionAllow)

	result, err := store.Lookup("unknown@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if result.Matched {
		t.Error("Lookup() Matched = true, want false for default allow")
	}
}

// Cycle 9: Property-Based Test - Allowlist Invariant
// Property: In deny mode, unlisted subjects ALWAYS return ErrEntitlementNotFound
func TestInMemoryEntitlementStore_Property_AllowlistInvariant(t *testing.T) {
	f := func(subject string, listedSubjects []string) bool {
		if subject == "" {
			return true
		}
		for _, s := range listedSubjects {
			if s == subject {
				return true // skip if subject is in list
			}
		}

		store := NewInMemoryEntitlementStore()
		store.SetDefaultAction(domain.DefaultActionDeny)
		for _, s := range listedSubjects {
			if s != "" {
				store.Add(domain.Entitlement{Subject: s, Roles: []string{"user"}})
			}
		}

		_, err := store.Lookup(subject)
		return errors.Is(err, domain.ErrEntitlementNotFound)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 10: Property-Based Test - Blocklist Invariant
// Property: In allow mode, unlisted subjects ALWAYS return Matched=false (not error)
func TestInMemoryEntitlementStore_Property_BlocklistInvariant(t *testing.T) {
	f := func(subject string, blockedSubjects []string) bool {
		if subject == "" || slices.Contains(blockedSubjects, subject) {
			return true
		}

		store := NewInMemoryEntitlementStore()
		store.SetDefaultAction(domain.DefaultActionAllow)
		// In blocklist mode, listed subjects would be blocked (separate test)

		result, err := store.Lookup(subject)
		return err == nil && !result.Matched
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 11: Property-Based Test - Exact Match Precedence
// Property: Exact match ALWAYS takes precedence over pattern match
func TestInMemoryEntitlementStore_Property_ExactPrecedence(t *testing.T) {
	f := func(subject string) bool {
		if subject == "" {
			return true
		}

		store := NewInMemoryEntitlementStore()
		store.Add(domain.Entitlement{Pattern: "*", Roles: []string{"pattern"}})
		store.Add(domain.Entitlement{Subject: subject, Roles: []string{"exact"}})

		result, err := store.Lookup(subject)
		if err != nil {
			return false
		}
		return slices.Contains(result.Roles, "exact") && !slices.Contains(result.Roles, "pattern")
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 12: Property-Based Test - Pattern Determinism
// Property: Same input ALWAYS produces same output
func TestInMemoryEntitlementStore_Property_Determinism(t *testing.T) {
	f := func(subject string, seed int64) bool {
		if subject == "" {
			return true
		}

		makeStore := func() *InMemoryEntitlementStore {
			s := NewInMemoryEntitlementStore()
			s.Add(domain.Entitlement{Pattern: "*@a.edu", Roles: []string{"a"}})
			s.Add(domain.Entitlement{Pattern: "*@b.edu", Roles: []string{"b"}})
			return s
		}

		r1, e1 := makeStore().Lookup(subject)
		r2, e2 := makeStore().Lookup(subject)

		return (e1 == nil) == (e2 == nil) && reflect.DeepEqual(r1, r2)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Cycle 13: Property-Based Test - Concurrent Access
// Property: Lookup is safe under concurrent access
func TestInMemoryEntitlementStore_Property_ConcurrentInvariants(t *testing.T) {
	store := NewInMemoryEntitlementStore()
	store.Add(domain.Entitlement{Subject: "user@example.edu", Roles: []string{"user"}})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Lookup("user@example.edu")
		}()
	}
	wg.Wait()
	// No panic = pass (race detector will catch issues)
}



