package caddysamldisco

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
)

//go:embed templates/*.html
var embeddedTemplates embed.FS

// DiscoData holds data for rendering the discovery page template.
type DiscoData struct {
	IdPs            []IdPInfo
	ReturnURL       string
	RememberedIdPID string // Entity ID of the last-used IdP (from cookie)
}

// ErrorData holds data for rendering error page templates.
type ErrorData struct {
	Title   string
	Message string
}

// TemplateRenderer renders HTML templates for the discovery UI.
type TemplateRenderer struct {
	disco *template.Template
	err   *template.Template
}

// NewTemplateRenderer creates a renderer using embedded templates.
func NewTemplateRenderer() (*TemplateRenderer, error) {
	disco, err := template.ParseFS(embeddedTemplates, "templates/disco.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded disco.html: %w", err)
	}

	errTmpl, err := template.ParseFS(embeddedTemplates, "templates/error.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded error.html: %w", err)
	}

	return &TemplateRenderer{
		disco: disco,
		err:   errTmpl,
	}, nil
}

// NewTemplateRendererWithDir creates a renderer that loads custom templates
// from the given directory, falling back to embedded for missing files.
func NewTemplateRendererWithDir(dir string) (*TemplateRenderer, error) {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("templates directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("templates path is not a directory: %s", dir)
	}

	// Load disco template (custom or embedded fallback)
	disco, err := loadTemplate(dir, "disco.html")
	if err != nil {
		return nil, fmt.Errorf("load disco template: %w", err)
	}

	// Load error template (custom or embedded fallback)
	errTmpl, err := loadTemplate(dir, "error.html")
	if err != nil {
		return nil, fmt.Errorf("load error template: %w", err)
	}

	return &TemplateRenderer{
		disco: disco,
		err:   errTmpl,
	}, nil
}

// loadTemplate tries to load a template from the custom directory,
// falling back to the embedded version if the file doesn't exist.
func loadTemplate(dir, name string) (*template.Template, error) {
	customPath := filepath.Join(dir, name)

	// Check if custom template exists
	if _, err := os.Stat(customPath); err == nil {
		// Custom template exists, parse it
		tmpl, err := template.ParseFiles(customPath)
		if err != nil {
			return nil, fmt.Errorf("parse custom %s: %w", name, err)
		}
		return tmpl, nil
	}

	// Fall back to embedded template
	tmpl, err := template.ParseFS(embeddedTemplates, "templates/"+name)
	if err != nil {
		return nil, fmt.Errorf("parse embedded %s: %w", name, err)
	}
	return tmpl, nil
}

// RenderDisco renders the discovery page.
func (r *TemplateRenderer) RenderDisco(w io.Writer, data DiscoData) error {
	return r.disco.Execute(w, data)
}

// RenderError renders an error page.
func (r *TemplateRenderer) RenderError(w io.Writer, data ErrorData) error {
	return r.err.Execute(w, data)
}
