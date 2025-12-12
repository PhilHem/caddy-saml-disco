//go:build unit

package caddysamldisco

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cycle 1: Template Renderer with Embedded Templates

func TestNewTemplateRenderer_LoadsEmbeddedTemplates(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}
	if renderer == nil {
		t.Fatal("NewTemplateRenderer() returned nil")
	}
}

func TestTemplateRenderer_RenderDisco_WithIdPs(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	idps := []IdPInfo{
		{EntityID: "https://idp1.example.com", DisplayName: "University One"},
		{EntityID: "https://idp2.example.com", DisplayName: "College Two", Description: "A great college"},
	}

	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{IdPs: idps, ReturnURL: "/protected"})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	output := buf.String()

	// Verify IdP names appear
	if !strings.Contains(output, "University One") {
		t.Error("output should contain 'University One'")
	}
	if !strings.Contains(output, "College Two") {
		t.Error("output should contain 'College Two'")
	}

	// Verify entity IDs appear (as data attributes)
	if !strings.Contains(output, "https://idp1.example.com") {
		t.Error("output should contain entity ID 'https://idp1.example.com'")
	}
	if !strings.Contains(output, "https://idp2.example.com") {
		t.Error("output should contain entity ID 'https://idp2.example.com'")
	}

	// Verify description appears
	if !strings.Contains(output, "A great college") {
		t.Error("output should contain description 'A great college'")
	}

	// Verify return URL is in the output
	if !strings.Contains(output, "/protected") {
		t.Error("output should contain return URL '/protected'")
	}
}

func TestTemplateRenderer_RenderDisco_EmptyIdPs(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{IdPs: []IdPInfo{}, ReturnURL: "/"})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	output := buf.String()

	// Should show empty state message
	if !strings.Contains(output, "No identity providers available") {
		t.Error("output should contain empty state message")
	}

	// Should not have search input when no IdPs
	if strings.Contains(output, `id="search"`) {
		t.Error("output should not contain search input when no IdPs")
	}
}

func TestTemplateRenderer_RenderDisco_EscapesHTML(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	// Malicious IdP name that could be XSS attack
	idps := []IdPInfo{
		{EntityID: "https://evil.com", DisplayName: "<script>alert('xss')</script>"},
	}

	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{IdPs: idps, ReturnURL: "/"})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	output := buf.String()

	// Raw script tag should NOT appear (should be escaped)
	if strings.Contains(output, "<script>alert") {
		t.Error("output should escape <script> tags (XSS vulnerability)")
	}

	// Escaped version should appear
	if !strings.Contains(output, "&lt;script&gt;") {
		t.Error("output should contain escaped script tag")
	}
}

func TestTemplateRenderer_RenderDisco_WithLogo(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	idps := []IdPInfo{
		{EntityID: "https://idp.example.com", DisplayName: "Test IdP", LogoURL: "https://example.com/logo.png"},
	}

	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{IdPs: idps, ReturnURL: "/"})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	output := buf.String()

	// Verify logo URL appears in img tag
	if !strings.Contains(output, "https://example.com/logo.png") {
		t.Error("output should contain logo URL")
	}
	if !strings.Contains(output, "<img") {
		t.Error("output should contain img tag for logo")
	}
}

func TestTemplateRenderer_RenderError_BasicError(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	var buf bytes.Buffer
	err = renderer.RenderError(&buf, ErrorData{
		Title:   "Authentication Failed",
		Message: "Your session has expired. Please try again.",
	})
	if err != nil {
		t.Fatalf("RenderError() error = %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Authentication Failed") {
		t.Error("output should contain error title")
	}
	if !strings.Contains(output, "Your session has expired") {
		t.Error("output should contain error message")
	}
}

func TestTemplateRenderer_RenderError_EscapesHTML(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("NewTemplateRenderer() error = %v", err)
	}

	var buf bytes.Buffer
	err = renderer.RenderError(&buf, ErrorData{
		Title:   "<script>alert('xss')</script>",
		Message: "Normal message",
	})
	if err != nil {
		t.Fatalf("RenderError() error = %v", err)
	}

	output := buf.String()

	// Raw script tag should NOT appear
	if strings.Contains(output, "<script>alert") {
		t.Error("output should escape <script> tags in title (XSS vulnerability)")
	}
}

// Cycle 2: Custom Template Override

func TestNewTemplateRendererWithDir_LoadsCustomTemplates(t *testing.T) {
	// Create temp directory with custom template
	tmpDir := t.TempDir()

	customDisco := `<!DOCTYPE html><html><body><h1>CUSTOM DISCO PAGE</h1>{{range .IdPs}}<div>{{.DisplayName}}</div>{{end}}</body></html>`
	err := os.WriteFile(filepath.Join(tmpDir, "disco.html"), []byte(customDisco), 0644)
	if err != nil {
		t.Fatalf("failed to write custom disco.html: %v", err)
	}

	customError := `<!DOCTYPE html><html><body><h1>CUSTOM ERROR: {{.Title}}</h1></body></html>`
	err = os.WriteFile(filepath.Join(tmpDir, "error.html"), []byte(customError), 0644)
	if err != nil {
		t.Fatalf("failed to write custom error.html: %v", err)
	}

	renderer, err := NewTemplateRendererWithDir(tmpDir)
	if err != nil {
		t.Fatalf("NewTemplateRendererWithDir() error = %v", err)
	}

	// Verify custom disco template is used
	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{
		IdPs:      []IdPInfo{{EntityID: "test", DisplayName: "Test IdP"}},
		ReturnURL: "/",
	})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	if !strings.Contains(buf.String(), "CUSTOM DISCO PAGE") {
		t.Error("should use custom disco template")
	}

	// Verify custom error template is used
	buf.Reset()
	err = renderer.RenderError(&buf, ErrorData{Title: "Test Error", Message: "msg"})
	if err != nil {
		t.Fatalf("RenderError() error = %v", err)
	}

	if !strings.Contains(buf.String(), "CUSTOM ERROR: Test Error") {
		t.Error("should use custom error template")
	}
}

func TestNewTemplateRendererWithDir_FallsBackToEmbedded(t *testing.T) {
	// Create temp directory with only disco.html (no error.html)
	tmpDir := t.TempDir()

	customDisco := `<!DOCTYPE html><html><body><h1>CUSTOM DISCO ONLY</h1>{{range .IdPs}}<div>{{.DisplayName}}</div>{{end}}</body></html>`
	err := os.WriteFile(filepath.Join(tmpDir, "disco.html"), []byte(customDisco), 0644)
	if err != nil {
		t.Fatalf("failed to write custom disco.html: %v", err)
	}

	renderer, err := NewTemplateRendererWithDir(tmpDir)
	if err != nil {
		t.Fatalf("NewTemplateRendererWithDir() error = %v", err)
	}

	// Verify custom disco template is used
	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{
		IdPs:      []IdPInfo{{EntityID: "test", DisplayName: "Test IdP"}},
		ReturnURL: "/",
	})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	if !strings.Contains(buf.String(), "CUSTOM DISCO ONLY") {
		t.Error("should use custom disco template")
	}

	// Verify embedded error template is used (fallback)
	buf.Reset()
	err = renderer.RenderError(&buf, ErrorData{Title: "Test Error", Message: "msg"})
	if err != nil {
		t.Fatalf("RenderError() error = %v", err)
	}

	// Should NOT contain "CUSTOM" since we're using embedded
	if strings.Contains(buf.String(), "CUSTOM") {
		t.Error("should fall back to embedded error template")
	}
	// Should contain something from the embedded template
	if !strings.Contains(buf.String(), "Test Error") {
		t.Error("embedded error template should render the title")
	}
}

func TestNewTemplateRendererWithDir_InvalidTemplate_ReturnsError(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid template syntax
	invalidTemplate := `<!DOCTYPE html><html><body>{{.InvalidSyntax`
	err := os.WriteFile(filepath.Join(tmpDir, "disco.html"), []byte(invalidTemplate), 0644)
	if err != nil {
		t.Fatalf("failed to write invalid disco.html: %v", err)
	}

	_, err = NewTemplateRendererWithDir(tmpDir)
	if err == nil {
		t.Error("NewTemplateRendererWithDir() should return error for invalid template")
	}
}

func TestNewTemplateRendererWithDir_NonexistentDir_ReturnsError(t *testing.T) {
	_, err := NewTemplateRendererWithDir("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("NewTemplateRendererWithDir() should return error for nonexistent directory")
	}
}

func TestNewTemplateRendererWithDir_EmptyDir_UsesEmbedded(t *testing.T) {
	// Empty directory should fall back to all embedded templates
	tmpDir := t.TempDir()

	renderer, err := NewTemplateRendererWithDir(tmpDir)
	if err != nil {
		t.Fatalf("NewTemplateRendererWithDir() error = %v", err)
	}

	// Verify embedded disco template is used
	var buf bytes.Buffer
	err = renderer.RenderDisco(&buf, DiscoData{
		IdPs:      []IdPInfo{{EntityID: "test", DisplayName: "Test IdP"}},
		ReturnURL: "/",
	})
	if err != nil {
		t.Fatalf("RenderDisco() error = %v", err)
	}

	// Should contain something from the embedded template (the title)
	if !strings.Contains(buf.String(), "Select your Identity Provider") {
		t.Error("should use embedded disco template when custom dir is empty")
	}
}
