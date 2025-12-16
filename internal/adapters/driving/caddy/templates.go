package caddy

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

//go:embed templates/*.html
var embeddedTemplates embed.FS

// DiscoData holds data for rendering the discovery page template.
type DiscoData struct {
	IdPs            []domain.IdPInfo
	PinnedIdPs      []domain.IdPInfo // Pinned IdPs shown prominently (filtered from IdPs)
	ReturnURL       string
	RememberedIdPID string           // Entity ID of the last-used IdP (from cookie)
	RememberedIdP   *domain.IdPInfo  // Full IdP info for remembered IdP
	AltLogins       []AltLoginOption // Alternative login methods
	ServiceName     string           // Service name for branding
}

// AltLoginOption represents an alternative login method for the discovery UI.
type AltLoginOption struct {
	URL   string
	Label string
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
	return NewTemplateRendererWithTemplate("")
}

// NewTemplateRendererWithTemplate creates a renderer using the specified discovery template.
// Supported templates:
//   - "" (empty) or "default": uses disco.html
//   - "fels": uses disco-fels.html (FeLS-style with autocomplete)
//
// Error templates always use the default error.html.
func NewTemplateRendererWithTemplate(templateName string) (*TemplateRenderer, error) {
	// Select the disco template based on name
	var discoFile string
	switch templateName {
	case "", "default":
		discoFile = "templates/disco.html"
	case "fels":
		discoFile = "templates/disco-fels.html"
	default:
		return nil, fmt.Errorf("unknown discovery template: %q (supported: \"default\", \"fels\")", templateName)
	}

	disco, err := template.ParseFS(embeddedTemplates, discoFile)
	if err != nil {
		return nil, fmt.Errorf("parse embedded %s: %w", discoFile, err)
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
