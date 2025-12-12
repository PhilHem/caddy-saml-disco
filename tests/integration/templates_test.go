//go:build integration

package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	caddysamldisco "github.com/philiph/caddy-saml-disco"
)

// TestTemplates_CustomDir_UsesCustomDiscoveryTemplate verifies that
// when a custom templates directory is provided, the custom disco.html is used.
func TestTemplates_CustomDir_UsesCustomDiscoveryTemplate(t *testing.T) {
	// Create temp directory with custom template
	tmpDir := t.TempDir()

	customMarker := "CUSTOM_INTEGRATION_TEST_MARKER_12345"
	customTemplate := `<!DOCTYPE html>
<html>
<head><title>Custom Discovery</title></head>
<body>
<div id="` + customMarker + `"></div>
<h1>Custom IdP Selection</h1>
{{range .IdPs}}
<div class="custom-idp">{{.DisplayName}}</div>
{{end}}
</body>
</html>`

	err := os.WriteFile(filepath.Join(tmpDir, "disco.html"), []byte(customTemplate), 0644)
	if err != nil {
		t.Fatalf("write custom template: %v", err)
	}

	// Create renderer with custom directory
	renderer, err := caddysamldisco.NewTemplateRendererWithDir(tmpDir)
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	// Create plugin with custom renderer
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))
	disco.SetTemplateRenderer(renderer)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	// Request discovery UI
	resp, err := http.Get(server.URL + "/saml/disco")
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify custom marker appears
	if !strings.Contains(bodyStr, customMarker) {
		t.Error("response should contain custom template marker")
	}

	// Verify custom structure
	if !strings.Contains(bodyStr, "Custom IdP Selection") {
		t.Error("response should contain custom title")
	}

	if !strings.Contains(bodyStr, "custom-idp") {
		t.Error("response should contain custom IdP class")
	}
}

// TestTemplates_DefaultTemplate_HasExpectedStructure verifies that
// the embedded default template renders with expected elements.
func TestTemplates_DefaultTemplate_HasExpectedStructure(t *testing.T) {
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))
	disco.SetTemplateRenderer(testTemplateRenderer(t))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/saml/disco")
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify expected elements
	requiredElements := []string{
		`<html`,
		`id="search"`,           // Search input
		`idp-list`,              // IdP list container
		`idp-item`,              // IdP items
		`data-entity-id`,        // Entity ID data attribute
		`/saml/api/select`,      // Select API endpoint in JS
		`Select your Identity Provider`, // Title
	}

	for _, elem := range requiredElements {
		if !strings.Contains(bodyStr, elem) {
			t.Errorf("response should contain %q", elem)
		}
	}
}

// TestTemplates_CustomDir_FallsBackForMissingTemplate verifies that
// when only disco.html is provided, error.html falls back to embedded.
func TestTemplates_CustomDir_FallsBackForMissingTemplate(t *testing.T) {
	// Create temp directory with only disco.html (no error.html)
	tmpDir := t.TempDir()

	customDisco := `<!DOCTYPE html><html><body>CUSTOM_DISCO_ONLY</body></html>`
	err := os.WriteFile(filepath.Join(tmpDir, "disco.html"), []byte(customDisco), 0644)
	if err != nil {
		t.Fatalf("write custom template: %v", err)
	}

	// Should succeed even without error.html
	renderer, err := caddysamldisco.NewTemplateRendererWithDir(tmpDir)
	if err != nil {
		t.Fatalf("create renderer should succeed with partial custom templates: %v", err)
	}

	// Verify disco uses custom
	disco := &caddysamldisco.SAMLDisco{}
	disco.SetMetadataStore(loadFileMetadataStore(t, "../../testdata/dfn-aai-sample.xml"))
	disco.SetTemplateRenderer(renderer)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disco.ServeHTTP(w, r, nil)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL + "/saml/disco")
	if err != nil {
		t.Fatalf("GET /saml/disco: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "CUSTOM_DISCO_ONLY") {
		t.Error("should use custom disco template")
	}
}
