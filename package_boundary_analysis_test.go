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
// ARCH-010: Package Boundary Confusion Analysis
// =============================================================================
//
// This test analyzes root package test files to detect mixed imports:
// tests that import both root package (caddysamldisco) AND internal packages
// directly. This creates ambiguity about which code path is being tested.

// TestPackageBoundary_MixedImports detects test files with mixed imports.
func TestPackageBoundary_MixedImports(t *testing.T) {
	rootDir := "."
	testFiles, err := findTestFiles(rootDir)
	if err != nil {
		t.Fatalf("Failed to find test files: %v", err)
	}

	mixedImportFiles := []string{}
	internalPrefix := "github.com/philiph/caddy-saml-disco/internal/"

	for _, testFile := range testFiles {
		imports, err := parseImports(testFile)
		if err != nil {
			t.Logf("Warning: Failed to parse %s: %v", testFile, err)
			continue
		}

		hasInternalImport := false

		for _, imp := range imports {
			// Check if it's an internal package import
			// Tests in root package ARE the root package, so they don't import it
			// But they might import internal packages directly, which creates boundary confusion
			if strings.HasPrefix(imp, internalPrefix) {
				hasInternalImport = true
				break
			}
		}

		// For root package tests, using internal imports directly is the issue
		// (they should use root package re-exports instead)
		if hasInternalImport && isRootPackageTest(testFile) {
			mixedImportFiles = append(mixedImportFiles, testFile)
		}
	}

	if len(mixedImportFiles) > 0 {
		t.Errorf("Found %d test files in root package with direct internal imports (should use root package re-exports instead):\n%s",
			len(mixedImportFiles), strings.Join(mixedImportFiles, "\n"))
		t.Logf("These files import internal packages directly, creating ambiguity about which code path is being tested.")
		t.Logf("Tests should use root package re-exports (e.g., caddysamldisco.IdPInfo) instead of direct internal imports (e.g., domain.IdPInfo).")
	} else {
		t.Log("No mixed imports found - all root package tests use consistent import paths.")
	}
}

// findTestFiles finds all *_test.go files in the root directory.
func findTestFiles(rootDir string) ([]string, error) {
	var testFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only check files in root directory (not subdirectories)
		if info.IsDir() && path != rootDir {
			return filepath.SkipDir
		}

		if !info.IsDir() && strings.HasSuffix(path, "_test.go") {
			testFiles = append(testFiles, path)
		}

		return nil
	})

	return testFiles, err
}

// isRootPackageTest checks if a test file is in the root package.
func isRootPackageTest(filePath string) bool {
	// Check if file is in root directory (not in subdirectories)
	dir := filepath.Dir(filePath)
	return dir == "." || dir == ""
}

// parseImports extracts import paths from a Go source file.
func parseImports(filePath string) ([]string, error) {
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

// TestPackageBoundary_ImportConsistency checks that root package test files
// use consistent import patterns (either all root re-exports or all internal,
// but not mixed).
func TestPackageBoundary_ImportConsistency(t *testing.T) {
	rootDir := "."
	testFiles, err := findTestFiles(rootDir)
	if err != nil {
		t.Fatalf("Failed to find test files: %v", err)
	}

	inconsistentFiles := []struct {
		file    string
		imports []string
	}{}

	internalPrefix := "github.com/philiph/caddy-saml-disco/internal/"

	for _, testFile := range testFiles {
		if !isRootPackageTest(testFile) {
			continue
		}

		imports, err := parseImports(testFile)
		if err != nil {
			continue
		}

		hasInternalImport := false
		for _, imp := range imports {
			if strings.HasPrefix(imp, internalPrefix) {
				hasInternalImport = true
				break
			}
		}

		if hasInternalImport {
			// Check if file also uses root package types (which would indicate mixing)
			// This is a heuristic: if file imports internal packages, it should
			// be using them consistently, not mixing with root package re-exports
			inconsistentFiles = append(inconsistentFiles, struct {
				file    string
				imports []string
			}{testFile, imports})
		}
	}

	if len(inconsistentFiles) > 0 {
		t.Logf("Found %d root package test files with direct internal imports:", len(inconsistentFiles))
		for _, item := range inconsistentFiles {
			t.Logf("  - %s imports: %v", item.file, item.imports)
		}
		t.Logf("These files should be reviewed to ensure they use root package re-exports consistently.")
	} else {
		t.Log("All root package test files use consistent import patterns.")
	}
}



