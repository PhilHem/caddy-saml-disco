//go:build unit

package caddysamldisco

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// mockMetadataStore is a test double for MetadataStore.
type mockMetadataStore struct {
	idps []IdPInfo
}

func (m *mockMetadataStore) GetIdP(entityID string) (*IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, ErrIdPNotFound
}

func (m *mockMetadataStore) ListIdPs(filter string) ([]IdPInfo, error) {
	return m.idps, nil
}

func (m *mockMetadataStore) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStore) Health() MetadataHealth {
	return MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// mockNextHandler is a test double for the next handler in the middleware chain.
type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*mockNextHandler)(nil)

// capturedHeaders captures headers passed to the downstream handler.
type capturedHeaders struct {
	called  bool
	headers http.Header
}

func (c *capturedHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	c.called = true
	c.headers = r.Header.Clone()
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*capturedHeaders)(nil)

// testTemplateRenderer returns a template renderer for tests.
// This uses the embedded templates.
func testTemplateRenderer(t *testing.T) *TemplateRenderer {
	t.Helper()
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("failed to create template renderer: %v", err)
	}
	return renderer
}

// boolPtr returns a pointer to the given bool value.
// Helper function for tests (boolPtr is not exported from caddy package).
func boolPtr(v bool) *bool {
	b := v
	return &b
}

// mockMetadataStoreWithFilter is a mock that actually implements search filtering.
type mockMetadataStoreWithFilter struct {
	idps []IdPInfo
}

func (m *mockMetadataStoreWithFilter) GetIdP(entityID string) (*IdPInfo, error) {
	for i := range m.idps {
		if m.idps[i].EntityID == entityID {
			return &m.idps[i], nil
		}
	}
	return nil, ErrIdPNotFound
}

func (m *mockMetadataStoreWithFilter) ListIdPs(filter string) ([]IdPInfo, error) {
	if filter == "" {
		return m.idps, nil
	}
	filter = strings.ToLower(filter)
	var result []IdPInfo
	for _, idp := range m.idps {
		if strings.Contains(strings.ToLower(idp.DisplayName), filter) ||
			strings.Contains(strings.ToLower(idp.EntityID), filter) {
			result = append(result, idp)
		}
	}
	return result, nil
}

func (m *mockMetadataStoreWithFilter) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockMetadataStoreWithFilter) Health() MetadataHealth {
	return MetadataHealth{IsFresh: true, IdPCount: len(m.idps)}
}

// mockCloseableMetadataStore is a test double that implements Close().
type mockCloseableMetadataStore struct {
	mockMetadataStore
	closed bool
}

func (m *mockCloseableMetadataStore) Close() error {
	m.closed = true
	return nil
}
