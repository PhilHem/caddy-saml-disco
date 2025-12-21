// Package tra provides Test Responsibility Anchor enforcement for Go tests.
//
// Usage:
//
//	func TestCreateOrder(t *testing.T) {
//	    tra.Require(t, "UseCase.CreateOrder")
//	    // ... test code
//	}
//
// Installation:
//
//	Copy this file to your project, e.g., internal/testutil/tra/tra.go
package tra

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// Valid TRA namespace prefixes
var validPrefixes = []string{
	"Domain.Invariant.",
	"Domain.Policy.",
	"UseCase.",
	"Port.",
	"Adapter.",
	"Contract.",
}

// Anchor tracking for summary report
var (
	mu       sync.Mutex
	anchors  = make(map[string][]string) // anchor -> test names
	enforced = make(map[string]bool)     // test name -> has TRA
)

// Require declares the Test Responsibility Anchor for this test.
// It must be called exactly once per test, and the anchor must follow
// the canonical namespace format.
//
// Valid prefixes:
//   - Domain.Invariant.*
//   - Domain.Policy.*
//   - UseCase.*
//   - Port.*
//   - Adapter.*
//   - Contract.*
func Require(t testing.TB, anchor string) {
	t.Helper()

	testName := t.Name()

	mu.Lock()
	defer mu.Unlock()

	// Check for duplicate TRA call in same test
	if enforced[testName] {
		t.Fatalf("TRA: Multiple Require() calls in %s. Each test must have exactly one responsibility.", testName)
	}
	enforced[testName] = true

	// Validate anchor format
	if anchor == "" {
		t.Fatal("TRA: Anchor cannot be empty")
	}

	valid := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(anchor, prefix) {
			valid = true
			break
		}
	}

	if !valid {
		t.Fatalf("TRA: Invalid anchor %q. Must start with one of: %v", anchor, validPrefixes)
	}

	// Track for reporting
	anchors[anchor] = append(anchors[anchor], testName)
}

// RequireLegacy marks a test as legacy (no TRA yet).
// Use only for migration. Never add new legacy tests.
func RequireLegacy(t testing.TB) {
	t.Helper()

	testName := t.Name()

	mu.Lock()
	defer mu.Unlock()

	if enforced[testName] {
		t.Fatalf("TRA: Cannot have both Require() and RequireLegacy() in %s", testName)
	}
	enforced[testName] = true
}

// AssertWith includes the TRA in assertion failure messages for navigability.
//
// Usage:
//
//	if !order.IsPayable() {
//	    t.Fatal(tra.AssertWith("Domain.Invariant.OrderMustBePayable", "order is not payable"))
//	}
func AssertWith(anchor, msg string) string {
	return fmt.Sprintf("%s [violates %s]", msg, anchor)
}

// PrintSummary prints TRA statistics. Call from TestMain if desired.
//
//	func TestMain(m *testing.M) {
//	    code := m.Run()
//	    tra.PrintSummary()
//	    os.Exit(code)
//	}
func PrintSummary() {
	mu.Lock()
	defer mu.Unlock()

	if len(anchors) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "\n=== TRA Summary ===")

	// Count by namespace
	namespaces := make(map[string]int)
	total := 0
	for anchor, tests := range anchors {
		parts := strings.SplitN(anchor, ".", 2)
		ns := parts[0]
		namespaces[ns] += len(tests)
		total += len(tests)
	}

	fmt.Fprintf(os.Stderr, "Total anchored tests: %d\n", total)
	fmt.Fprintln(os.Stderr, "By namespace:")
	for ns, count := range namespaces {
		fmt.Fprintf(os.Stderr, "  %s: %d\n", ns, count)
	}

	// Warn about over-testing
	for anchor, tests := range anchors {
		if len(tests) > 3 {
			fmt.Fprintf(os.Stderr, "Warning: %q has %d tests - consider if all are necessary\n", anchor, len(tests))
		}
	}
}

// Reset clears all tracking. Useful for testing the TRA package itself.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	anchors = make(map[string][]string)
	enforced = make(map[string]bool)
}
