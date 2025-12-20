//go:build unit

package caddysamldisco

import (
	"fmt"
	"sync"
	"testing"
)

// =============================================================================
// ARCH-010: Concurrency Testing Gaps - Port Interface Thread-Safety
// =============================================================================

// TestAttributeMapper_Concurrency_ThreadSafetyViaPort tests ARCH-010:
// Verifies that AttributeMapper port interface is thread-safe when the same
// instance is accessed concurrently through the port interface.
// This test ensures that tests using port interfaces properly verify thread-safety
// rather than bypassing port contracts.
func TestAttributeMapper_Concurrency_ThreadSafetyViaPort(t *testing.T) {
	const numGoroutines = 100
	const numCallsPerGoroutine = 10

	// Create a single AttributeMapper instance (shared across goroutines)
	mapper := newTestAttributeMapper()

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
				headerNameSuffix := sanitizeForHeaderName(fmt.Sprintf("Header%d_%d", id, j))
				if headerNameSuffix == "" {
					headerNameSuffix = "Header"
				}
				headerName := "X-" + headerNameSuffix

				attrs := map[string][]string{attrKey: {attrVal}}
				mappings := []PortAttributeMapping{
					{SAMLAttribute: attrKey, HeaderName: headerName},
				}

				// Test MapAttributesToHeaders concurrently on shared instance
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
		t.Errorf("encountered %d errors during concurrent access", errorCount)
	}
}



