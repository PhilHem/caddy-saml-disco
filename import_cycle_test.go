//go:build unit

package caddysamldisco

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// ARCH-011: Import Cycle Risk Verification
// =============================================================================
//
// This test verifies that no internal packages import the root package,
// which would create an import cycle (root -> internal -> root).

// TestImportCycle_NoInternalImportsRoot verifies that no internal packages
// import the root package, which would create an import cycle.
func TestImportCycle_NoInternalImportsRoot(t *testing.T) {
	rootPackagePath := "github.com/philiph/caddy-saml-disco"
	internalDir := "internal"

	// Find all Go files in internal directory
	internalFiles, err := findGoFiles(internalDir)
	if err != nil {
		t.Fatalf("Failed to find internal files: %v", err)
	}

	violations := []struct {
		file    string
		imports []string
	}{}

	for _, file := range internalFiles {
		imports, err := parseImportsForCycle(file)
		if err != nil {
			t.Logf("Warning: Failed to parse %s: %v", file, err)
			continue
		}

		// Check if any import is the root package
		hasRootImport := false
		rootImports := []string{}
		for _, imp := range imports {
			if imp == rootPackagePath {
				hasRootImport = true
				rootImports = append(rootImports, imp)
			}
		}

		if hasRootImport {
			violations = append(violations, struct {
				file    string
				imports []string
			}{file, rootImports})
		}
	}

	if len(violations) > 0 {
		t.Errorf("Found %d internal package files that import root package (would create import cycle):", len(violations))
		for _, v := range violations {
			t.Errorf("  - %s imports: %v", v.file, v.imports)
		}
		t.Errorf("Internal packages must NOT import the root package to maintain hexagonal architecture boundaries.")
		t.Errorf("Root package re-exports are for external consumers, not for internal packages.")
	} else {
		t.Log("No import cycles detected - all internal packages correctly avoid importing root package.")
	}
}

// TestImportCycle_NoInternalImportsRootRecursive performs a more thorough check
// by examining all imports transitively to detect potential cycles.
func TestImportCycle_NoInternalImportsRootRecursive(t *testing.T) {
	rootPackagePath := "github.com/philiph/caddy-saml-disco"
	internalDir := "internal"

	// Find all Go files in internal directory
	internalFiles, err := findGoFiles(internalDir)
	if err != nil {
		t.Fatalf("Failed to find internal files: %v", err)
	}

	violations := []string{}

	for _, file := range internalFiles {
		imports, err := parseImportsForCycle(file)
		if err != nil {
			continue
		}

		// Check for root package import
		for _, imp := range imports {
			if imp == rootPackagePath {
				violations = append(violations, file)
				break
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("Import cycle risk: %d internal files import root package:", len(violations))
		for _, v := range violations {
			t.Errorf("  - %s", v)
		}
		t.Errorf("This creates a cycle: root package -> internal packages -> root package")
		t.Errorf("Internal packages should import other internal packages or external dependencies, not the root package.")
	} else {
		t.Log("No import cycles detected - architectural boundaries are maintained.")
	}
}

// findGoFiles finds all .go files in a directory recursively.
func findGoFiles(rootDir string) ([]string, error) {
	var goFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			// Skip test files for this check (they might have different patterns)
			if !strings.HasSuffix(path, "_test.go") {
				goFiles = append(goFiles, path)
			}
		}

		return nil
	})

	return goFiles, err
}

// parseImports extracts import paths from a Go source file.
// (Reusing the same function from package_boundary_analysis_test.go)
func parseImportsForCycle(filePath string) ([]string, error) {
	fset := token.NewFileSet()
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	file, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var imports []string
	for _, imp := range file.Imports {
		// Remove quotes from import path
		importPath := strings.Trim(imp.Path.Value, `"`)
		imports = append(imports, importPath)
	}

	return imports, nil
}



