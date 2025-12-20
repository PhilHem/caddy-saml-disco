//go:build unit

package caddysamldisco

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// =============================================================================
// ARCH-013 through ARCH-016: Edge Case Tests for Root Package Re-exports
// =============================================================================
//
// These tests verify edge cases that could cause bugs even if basic type alias
// equivalence tests pass. They test specific scenarios mentioned in KNOWN_ISSUES.md.

// TestRootReexport_EdgeCase_ContextValueTypeAssertion (ARCH-013) verifies that
// storing root package Session in context and retrieving with *domain.Session
// type assertion works correctly.
func TestRootReexport_EdgeCase_ContextValueTypeAssertion(t *testing.T) {
	// Create session using root package alias
	rootSession := &Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
		Attributes:  map[string]string{"email": "user@example.com"},
	}

	// Store in context
	ctx := context.WithValue(context.Background(), "session", rootSession)

	// Retrieve with *domain.Session type assertion
	retrieved, ok := ctx.Value("session").(*domain.Session)
	if !ok {
		t.Fatal("Type assertion to *domain.Session failed")
	}

	// Verify values match
	if retrieved.Subject != rootSession.Subject {
		t.Errorf("Subject mismatch: retrieved=%q, original=%q", retrieved.Subject, rootSession.Subject)
	}
	if retrieved.IdPEntityID != rootSession.IdPEntityID {
		t.Errorf("IdPEntityID mismatch: retrieved=%q, original=%q", retrieved.IdPEntityID, rootSession.IdPEntityID)
	}
}

// TestRootReexport_EdgeCase_TypeSwitch (ARCH-014) verifies that type switches
// work correctly with root package aliases vs internal types.
func TestRootReexport_EdgeCase_TypeSwitch(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{
			name:     "root package Session",
			value:    Session{Subject: "user@example.com"},
			expected: "Session",
		},
		{
			name:     "internal domain.Session",
			value:    domain.Session{Subject: "user@example.com"},
			expected: "Session",
		},
		{
			name:     "root package IdPInfo",
			value:    IdPInfo{EntityID: "https://idp.example.com"},
			expected: "IdPInfo",
		},
		{
			name:     "internal domain.IdPInfo",
			value:    domain.IdPInfo{EntityID: "https://idp.example.com"},
			expected: "IdPInfo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var result string
			// Note: Session and domain.Session are the same type (type alias),
			// so we only need to check one. Same for IdPInfo.
			switch tc.value.(type) {
			case Session:
				result = "Session"
			case IdPInfo:
				result = "IdPInfo"
			default:
				result = "unknown"
			}

			if result != tc.expected {
				t.Errorf("Type switch result = %q, want %q", result, tc.expected)
			}
		})
	}
}

// TestRootReexport_EdgeCase_JSONUnmarshaling (ARCH-015) verifies that JSON
// unmarshaling into root alias types and then asserting with internal types works.
func TestRootReexport_EdgeCase_JSONUnmarshaling(t *testing.T) {
	// Create JSON from root package Session
	rootSession := Session{
		Subject:     "user@example.com",
		IdPEntityID: "https://idp.example.com",
		Attributes:  map[string]string{"email": "user@example.com"},
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	jsonData, err := json.Marshal(rootSession)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Unmarshal into internal domain.Session
	var internalSession domain.Session
	if err := json.Unmarshal(jsonData, &internalSession); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify values match
	if internalSession.Subject != rootSession.Subject {
		t.Errorf("Subject mismatch: internal=%q, root=%q", internalSession.Subject, rootSession.Subject)
	}
	if internalSession.IdPEntityID != rootSession.IdPEntityID {
		t.Errorf("IdPEntityID mismatch: internal=%q, root=%q", internalSession.IdPEntityID, rootSession.IdPEntityID)
	}

	// Test reverse: unmarshal into root alias
	var rootSession2 Session
	if err := json.Unmarshal(jsonData, &rootSession2); err != nil {
		t.Fatalf("Unmarshal into root alias failed: %v", err)
	}

	if rootSession2.Subject != rootSession.Subject {
		t.Errorf("Subject mismatch after roundtrip: root2=%q, root=%q", rootSession2.Subject, rootSession.Subject)
	}
}

// TestRootReexport_EdgeCase_ReflectionConcurrent (ARCH-016) verifies that
// reflection-based type checks work correctly in concurrent contexts.
func TestRootReexport_EdgeCase_ReflectionConcurrent(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterationsPerGoroutine; j++ {
				// Create values using both root and internal types
				rootSession := Session{Subject: "user@example.com"}
				internalSession := domain.Session{Subject: "user@example.com"}

				// Use reflection to get types concurrently
				rootType := reflect.TypeOf(rootSession)
				internalType := reflect.TypeOf(internalSession)

				// Verify types are identical
				if rootType != internalType {
					errors <- fmt.Errorf("goroutine %d iteration %d: type mismatch: root=%v, internal=%v",
						id, j, rootType, internalType)
					continue
				}

				// Verify type names match
				if rootType.Name() != internalType.Name() {
					errors <- fmt.Errorf("goroutine %d iteration %d: type name mismatch: root=%q, internal=%q",
						id, j, rootType.Name(), internalType.Name())
					continue
				}

				// Verify type strings match
				if rootType.String() != internalType.String() {
					errors <- fmt.Errorf("goroutine %d iteration %d: type string mismatch: root=%q, internal=%q",
						id, j, rootType.String(), internalType.String())
					continue
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		if errorCount < 10 {
			t.Error(err)
		}
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("encountered %d errors during concurrent reflection checks", errorCount)
	}
}

// =============================================================================
// ARCH-033 + ARCH-034: Concurrency Tests for Root Package Re-exports
// =============================================================================
//
// These tests verify that root package re-exports maintain thread-safety and
// behavioral guarantees when accessed concurrently through port interfaces.

// TestRootReexport_Concurrency_PortInterfaceViaRoot (ARCH-033) verifies that
// AttributeMapper port interface accessed through root package re-exports
// maintains thread-safety guarantees when accessed concurrently.
func TestRootReexport_Concurrency_PortInterfaceViaRoot(t *testing.T) {
	const numGoroutines = 100
	const numCallsPerGoroutine = 10

	// Create AttributeMapper via root package re-export (not direct internal import)
	mapper := NewCaddyAttributeMapper()

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numCallsPerGoroutine*2) // *2 for both methods

	// Run concurrent calls with different inputs on the same mapper instance
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numCallsPerGoroutine; j++ {
				// Each goroutine uses unique attribute keys and values
				attrKey := fmt.Sprintf("attr%d_%d", id, j)
				attrVal := fmt.Sprintf("value%d_%d", id, j)
				// Use simple valid header name (no special characters needed for this test)
				headerName := fmt.Sprintf("X-Header%d-%d", id, j)

				attrs := map[string][]string{attrKey: {attrVal}}
				// Use PortAttributeMapping from root package (re-export)
				mappings := []PortAttributeMapping{
					{SAMLAttribute: attrKey, HeaderName: headerName},
				}

				// Test MapAttributesToHeaders concurrently on shared instance
				// Access through root package AttributeMapper interface
				result1, err1 := mapper.MapAttributesToHeaders(attrs, mappings)
				if err1 != nil {
					errors <- fmt.Errorf("goroutine %d call %d MapAttributesToHeaders: %w", id, j, err1)
					continue
				}

				// Verify result is correct
				expectedHeader := headerName
				if val, ok := result1[expectedHeader]; !ok || val != attrVal {
					errors <- fmt.Errorf("goroutine %d call %d: expected header %q with value %q, got %v", id, j, expectedHeader, attrVal, result1)
					continue
				}

				// Test MapAttributesToHeadersWithPrefix concurrently on shared instance
				prefix := "X-Prefix-"
				result2, err2 := mapper.MapAttributesToHeadersWithPrefix(attrs, mappings, prefix)
				if err2 != nil {
					errors <- fmt.Errorf("goroutine %d call %d MapAttributesToHeadersWithPrefix: %w", id, j, err2)
					continue
				}

				expectedPrefixedHeader := prefix + headerName
				if val, ok := result2[expectedPrefixedHeader]; !ok || val != attrVal {
					errors <- fmt.Errorf("goroutine %d call %d: expected prefixed header %q with value %q, got %v", id, j, expectedPrefixedHeader, attrVal, result2)
					continue
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)

	// Check for any errors
	errorCount := 0
	for err := range errors {
		if errorCount < 10 { // Only show first 10 errors
			t.Error(err)
		}
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("encountered %d errors during concurrent port interface access", errorCount)
	}
}

// TestRootReexport_Concurrency_TypeAliasJSONMarshaling (ARCH-034) verifies that
// JSON marshaling/unmarshaling of root package type aliases works correctly
// under concurrent access.
func TestRootReexport_Concurrency_TypeAliasJSONMarshaling(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine*2) // *2 for Session and IdPInfo

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterationsPerGoroutine; j++ {
				// Test Session type alias JSON marshaling concurrently
				rootSession := Session{
					Subject:     fmt.Sprintf("user%d_%d@example.com", id, j),
					IdPEntityID: fmt.Sprintf("https://idp%d.example.com", id),
					Attributes:  map[string]string{"email": fmt.Sprintf("user%d_%d@example.com", id, j)},
					IssuedAt:    time.Now(),
					ExpiresAt:   time.Now().Add(time.Hour),
				}

				// Marshal root package Session
				rootJSON, err1 := json.Marshal(rootSession)
				if err1 != nil {
					errors <- fmt.Errorf("goroutine %d iteration %d: root Session marshal failed: %w", id, j, err1)
					continue
				}

				// Unmarshal into internal domain.Session
				var internalSession domain.Session
				if err2 := json.Unmarshal(rootJSON, &internalSession); err2 != nil {
					errors <- fmt.Errorf("goroutine %d iteration %d: internal Session unmarshal failed: %w", id, j, err2)
					continue
				}

				// Verify values match
				if internalSession.Subject != rootSession.Subject {
					errors <- fmt.Errorf("goroutine %d iteration %d: Session Subject mismatch: root=%q, internal=%q", id, j, rootSession.Subject, internalSession.Subject)
					continue
				}

				// Test IdPInfo type alias JSON marshaling concurrently
				rootIdP := IdPInfo{
					EntityID:    fmt.Sprintf("https://idp%d.example.com", id),
					DisplayName: fmt.Sprintf("IdP %d-%d", id, j),
					SSOURL:      fmt.Sprintf("https://idp%d.example.com/sso", id),
				}

				// Marshal root package IdPInfo
				rootIdPJSON, err3 := json.Marshal(rootIdP)
				if err3 != nil {
					errors <- fmt.Errorf("goroutine %d iteration %d: root IdPInfo marshal failed: %w", id, j, err3)
					continue
				}

				// Unmarshal into internal domain.IdPInfo
				var internalIdP domain.IdPInfo
				if err4 := json.Unmarshal(rootIdPJSON, &internalIdP); err4 != nil {
					errors <- fmt.Errorf("goroutine %d iteration %d: internal IdPInfo unmarshal failed: %w", id, j, err4)
					continue
				}

				// Verify values match
				if internalIdP.EntityID != rootIdP.EntityID {
					errors <- fmt.Errorf("goroutine %d iteration %d: IdPInfo EntityID mismatch: root=%q, internal=%q", id, j, rootIdP.EntityID, internalIdP.EntityID)
					continue
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		if errorCount < 10 {
			t.Error(err)
		}
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("encountered %d errors during concurrent JSON marshaling", errorCount)
	}
}

// TestRootReexport_Concurrency_TypeAliasContextValues (ARCH-034) verifies that
// storing root package type aliases in context and retrieving with internal
// types works correctly under concurrent access.
func TestRootReexport_Concurrency_TypeAliasContextValues(t *testing.T) {
	const numGoroutines = 100
	const iterationsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*iterationsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterationsPerGoroutine; j++ {
				// Create session using root package alias
				rootSession := &Session{
					Subject:     fmt.Sprintf("user%d_%d@example.com", id, j),
					IdPEntityID: fmt.Sprintf("https://idp%d.example.com", id),
					Attributes:  map[string]string{"email": fmt.Sprintf("user%d_%d@example.com", id, j)},
				}

				// Store in context with unique key per goroutine/iteration
				key := fmt.Sprintf("session_%d_%d", id, j)
				ctx := context.WithValue(context.Background(), key, rootSession)

				// Retrieve with *domain.Session type assertion
				retrieved, ok := ctx.Value(key).(*domain.Session)
				if !ok {
					errors <- fmt.Errorf("goroutine %d iteration %d: type assertion to *domain.Session failed", id, j)
					continue
				}

				// Verify values match
				if retrieved.Subject != rootSession.Subject {
					errors <- fmt.Errorf("goroutine %d iteration %d: Subject mismatch: retrieved=%q, original=%q", id, j, retrieved.Subject, rootSession.Subject)
					continue
				}
				if retrieved.IdPEntityID != rootSession.IdPEntityID {
					errors <- fmt.Errorf("goroutine %d iteration %d: IdPEntityID mismatch: retrieved=%q, original=%q", id, j, retrieved.IdPEntityID, rootSession.IdPEntityID)
					continue
				}

				// Also test reverse: store internal type, retrieve with root alias
				internalSession := &domain.Session{
					Subject:     fmt.Sprintf("user%d_%d@example.com", id, j),
					IdPEntityID: fmt.Sprintf("https://idp%d.example.com", id),
					Attributes:  map[string]string{"email": fmt.Sprintf("user%d_%d@example.com", id, j)},
				}

				key2 := fmt.Sprintf("session2_%d_%d", id, j)
				ctx2 := context.WithValue(context.Background(), key2, internalSession)

				// Retrieve with *Session (root package alias) type assertion
				retrieved2, ok2 := ctx2.Value(key2).(*Session)
				if !ok2 {
					errors <- fmt.Errorf("goroutine %d iteration %d: type assertion to *Session (root alias) failed", id, j)
					continue
				}

				// Verify values match
				if retrieved2.Subject != internalSession.Subject {
					errors <- fmt.Errorf("goroutine %d iteration %d: Subject mismatch (reverse): retrieved=%q, original=%q", id, j, retrieved2.Subject, internalSession.Subject)
					continue
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		if errorCount < 10 {
			t.Error(err)
		}
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("encountered %d errors during concurrent context value access", errorCount)
	}
}


