//go:build unit

package domain

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDomainHasNoHTTPDependency verifies that the domain layer remains pure
// and does not import net/http or any framework dependencies.
// This is a critical architectural constraint for hexagonal architecture.
func TestDomainHasNoHTTPDependency(t *testing.T) {
	// Get the directory of this test file (domain package)
	domainDir := "."

	// Read all Go files in the domain directory
	entries, err := os.ReadDir(domainDir)
	if err != nil {
		t.Fatalf("Failed to read domain directory: %v", err)
	}

	fset := token.NewFileSet()

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}

		// Skip test files - they may need to verify behavior that relates to HTTP
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		filePath := filepath.Join(domainDir, entry.Name())

		// Parse the file
		f, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", entry.Name(), err)
		}

		// Check imports
		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)

			// Forbidden imports
			if importPath == "net/http" {
				t.Errorf("ARCHITECTURE VIOLATION: %s imports net/http - domain layer must be pure Go", entry.Name())
			}
			if strings.HasPrefix(importPath, "github.com/caddyserver/caddy") {
				t.Errorf("ARCHITECTURE VIOLATION: %s imports Caddy framework - domain layer must be pure Go", entry.Name())
			}
		}
	}
}
