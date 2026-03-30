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

// TestPackageBoundary_NoRootImportsFromInternal verifies that internal packages
// don't import root (covered by import_cycle_test.go) and that root test
// files don't import internal packages unnecessarily when a re-export exists.
//
// Root test files MAY import internal packages for symbols not re-exported.
// This test just logs which files do so for visibility.
func TestPackageBoundary_NoRootImportsFromInternal(t *testing.T) {
	rootDir := "."
	testFiles, err := findTestFiles(rootDir)
	if err != nil {
		t.Fatalf("Failed to find test files: %v", err)
	}

	internalPrefix := "github.com/philiph/caddy-saml-disco/internal/"
	testUtilPrefix := "github.com/philiph/caddy-saml-disco/internal/testutil/"

	for _, testFile := range testFiles {
		if !isRootPackageTest(testFile) {
			continue
		}

		imports, err := parseImports(testFile)
		if err != nil {
			continue
		}

		for _, imp := range imports {
			if strings.HasPrefix(imp, internalPrefix) && !strings.HasPrefix(imp, testUtilPrefix) {
				t.Logf("  %s imports %s (direct internal import)", testFile, imp)
			}
		}
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
		importPath := strings.Trim(imp.Path.Value, `"`)
		imports = append(imports, importPath)
	}

	return imports, nil
}
