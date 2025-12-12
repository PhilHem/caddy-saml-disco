//go:build unit

package caddysamldisco

import (
	"os"
	"strings"
	"testing"
)

func TestExampleCaddyfileIsValid(t *testing.T) {
	// Read the example Caddyfile
	content, err := os.ReadFile("examples/Caddyfile")
	if err != nil {
		t.Fatalf("failed to read examples/Caddyfile: %v", err)
	}

	// Verify the example contains session_duration directive
	if !strings.Contains(string(content), "session_duration") {
		t.Error("example Caddyfile should contain session_duration directive")
	}
}
