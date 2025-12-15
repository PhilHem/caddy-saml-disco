//go:build unit

package caddysamldisco

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// FakeClock is a controllable clock for testing cache TTL expiration.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock creates a FakeClock initialized to the current time.
func NewFakeClock() *FakeClock {
	return &FakeClock{now: time.Now()}
}

// Now returns the fake clock's current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by the specified duration.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestFileMetadataStore_Load(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0]

	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idp.EntityID, "https://idp.example.com/saml")
	}

	if idp.DisplayName != "Example IdP" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Example IdP")
	}

	if idp.SSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("SSOURL = %q, want %q", idp.SSOURL, "https://idp.example.com/saml/sso")
	}

	if idp.SSOBinding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
		t.Errorf("SSOBinding = %q, want HTTP-Redirect binding", idp.SSOBinding)
	}

	if len(idp.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestFileMetadataStore_GetIdP(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Found
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("wrong EntityID returned")
	}

	// Not found
	_, err = store.GetIdP("https://unknown.example.com")
	if err != ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound, got %v", err)
	}
}

func TestFileMetadataStore_ListIdPs_Filter(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		filter   string
		expected int
	}{
		{"", 1},        // no filter
		{"example", 1}, // matches display name and entity ID
		{"IdP", 1},     // matches display name (case insensitive)
		{"unknown", 0}, // no match
		{"EXAMPLE", 1}, // case insensitive
	}

	for _, tc := range tests {
		idps, err := store.ListIdPs(tc.filter)
		if err != nil {
			t.Errorf("ListIdPs(%q) failed: %v", tc.filter, err)
			continue
		}
		if len(idps) != tc.expected {
			t.Errorf("ListIdPs(%q) returned %d IdPs, want %d", tc.filter, len(idps), tc.expected)
		}
	}
}

func TestFileMetadataStore_Refresh(t *testing.T) {
	// Create a temp file for this test
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.xml")

	// Write initial metadata
	initialXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://first.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://first.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(initialXML), 0644); err != nil {
		t.Fatalf("write initial metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify initial state
	idp, err := store.GetIdP("https://first.example.com")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://first.example.com" {
		t.Errorf("initial EntityID wrong")
	}

	// Update the file
	updatedXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://second.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://second.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(updatedXML), 0644); err != nil {
		t.Fatalf("write updated metadata: %v", err)
	}

	// Refresh
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Verify updated state
	_, err = store.GetIdP("https://first.example.com")
	if err != ErrIdPNotFound {
		t.Error("old IdP should not be found after refresh")
	}

	idp, err = store.GetIdP("https://second.example.com")
	if err != nil {
		t.Fatalf("GetIdP() after refresh failed: %v", err)
	}
	if idp.EntityID != "https://second.example.com" {
		t.Errorf("refreshed EntityID wrong")
	}
}

func TestFileMetadataStore_FileNotFound(t *testing.T) {
	store := NewFileMetadataStore("/nonexistent/path/metadata.xml")
	err := store.Load()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestFileMetadataStore_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.xml")
	if err := os.WriteFile(path, []byte("not valid xml"), 0644); err != nil {
		t.Fatalf("write bad xml: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestFileMetadataStore_NoIdPDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sp-only.xml")
	// This is an SP metadata, not IdP
	xml := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/>
    </SPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(xml), 0644); err != nil {
		t.Fatalf("write sp metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()
	if err == nil {
		t.Error("expected error for SP-only metadata")
	}
}

// Aggregate metadata tests (EntitiesDescriptor with multiple IdPs)

func TestFileMetadataStore_Load_Aggregate(t *testing.T) {
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3", len(idps))
	}
}

func TestFileMetadataStore_GetIdP_Aggregate(t *testing.T) {
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Find specific IdP from aggregate
	idp, err := store.GetIdP("https://idp2.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://idp2.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idp.EntityID, "https://idp2.example.com/saml")
	}
	if idp.DisplayName != "Tech University" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Tech University")
	}
}

func TestFileMetadataStore_ListIdPs_Aggregate_Filter(t *testing.T) {
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		filter   string
		expected int
	}{
		{"", 3},           // no filter - all 3 IdPs
		{"University", 2}, // matches State University and Tech University
		{"Corporate", 1},  // matches Corporate Provider only
		{"unknown", 0},    // no match
	}

	for _, tc := range tests {
		idps, err := store.ListIdPs(tc.filter)
		if err != nil {
			t.Errorf("ListIdPs(%q) failed: %v", tc.filter, err)
			continue
		}
		if len(idps) != tc.expected {
			t.Errorf("ListIdPs(%q) returned %d IdPs, want %d", tc.filter, len(idps), tc.expected)
		}
	}
}

func TestFileMetadataStore_Load_Aggregate_SkipsSPs(t *testing.T) {
	// mixed-metadata.xml has 3 IdPs + 1 SP, should only load the 3 IdPs
	store := NewFileMetadataStore("testdata/mixed-metadata.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3 (SP should be skipped)", len(idps))
	}

	// Verify SP is not in the list
	for _, idp := range idps {
		if idp.EntityID == "https://sp.example.com" {
			t.Error("SP entity should have been skipped")
		}
	}
}

// Tests based on real DFN-AAI federation metadata structure
// Sample includes realistic mdui:UIInfo, mdrpi:RegistrationInfo, mdattr:EntityAttributes,
// shibmd:Scope, XML signatures, and multi-language support.

func TestFileMetadataStore_Load_DFNAAISample(t *testing.T) {
	// Based on https://www.aai.dfn.de/metadata/dfn-aai-idp-metadata.xml
	// Sample contains 6 IdPs + 1 SP (SP should be skipped)
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// 6 IdPs: FU Berlin, TUM, RWTH Aachen, Max Planck, AWI, Uni Freiburg
	// SP entity (sp.example.edu) should be skipped
	if len(idps) != 6 {
		t.Errorf("ListIdPs() returned %d IdPs, want 6", len(idps))
	}

	// Verify specific universities/institutions are present
	// Note: DisplayName now prefers mdui:DisplayName (English if available)
	tests := []struct {
		entityID    string
		displayName string
	}{
		{"https://identity.fu-berlin.de/idp-fub", "Freie Universität Berlin"},
		{"https://tumidp.lrz.de/idp/shibboleth", "Technical University of Munich (TUM)"},
		{"https://login.rz.rwth-aachen.de/shibboleth", "RWTH Aachen University"},              // English from mdui
		{"https://shib-idp.awi.de/idp/shibboleth", "Alfred Wegener Institute (AWI)"},          // English from mdui
		{"https://idp.mpg.de/idp/shibboleth", "Max Planck Society"},                           // English from mdui
		{"https://mylogin.uni-freiburg.de/shibboleth", "Albert-Ludwigs-Universität Freiburg"}, // German only
	}

	for _, tc := range tests {
		idp, err := store.GetIdP(tc.entityID)
		if err != nil {
			t.Errorf("GetIdP(%q) failed: %v", tc.entityID, err)
			continue
		}
		if idp.DisplayName != tc.displayName {
			t.Errorf("GetIdP(%q).DisplayName = %q, want %q", tc.entityID, idp.DisplayName, tc.displayName)
		}
	}
}

func TestFileMetadataStore_Load_DFNAAISample_FilterByUniversity(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Filter for "University" should match TUM and RWTH (2 of 6)
	// Both have "University" in their English mdui:DisplayName
	idps, err := store.ListIdPs("University")
	if err != nil {
		t.Fatalf("ListIdPs(University) failed: %v", err)
	}

	if len(idps) != 2 {
		t.Errorf("ListIdPs(University) returned %d IdPs, want 2 (TUM, RWTH)", len(idps))
	}

	// Filter for "Berlin" should match FU Berlin (1 of 6)
	idps, err = store.ListIdPs("Berlin")
	if err != nil {
		t.Fatalf("ListIdPs(Berlin) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(Berlin) returned %d IdPs, want 1", len(idps))
	}

	// Filter for German "Universität" matches all language variants:
	// FU Berlin, TUM (Technische Universität München), Uni Freiburg = 3 matches
	idps, err = store.ListIdPs("Universität")
	if err != nil {
		t.Fatalf("ListIdPs(Universität) failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs(Universität) returned %d IdPs, want 3", len(idps))
	}

	// Filter for "Hochschule" now matches RWTH's German name
	// "Rheinisch-Westfälische Technische Hochschule Aachen" in DisplayNames["de"]
	idps, err = store.ListIdPs("Hochschule")
	if err != nil {
		t.Fatalf("ListIdPs(Hochschule) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(Hochschule) returned %d IdPs, want 1 (RWTH German name)", len(idps))
	}

	// Filter for "Max Planck" should match Max Planck Society (1 of 6)
	idps, err = store.ListIdPs("Max Planck")
	if err != nil {
		t.Fatalf("ListIdPs(Max Planck) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(Max Planck) returned %d IdPs, want 1", len(idps))
	}
}

func TestFileMetadataStore_Load_NestedEntitiesDescriptor(t *testing.T) {
	// Tests nested EntitiesDescriptor structure (Universities > Labs hierarchy)
	store := NewFileMetadataStore("testdata/nested-metadata.xml")

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Should find: 1 top-level + 2 in Universities + 1 in Research + 1 in Labs = 5 IdPs
	// (SP in Universities group should be skipped)
	if len(idps) != 5 {
		t.Errorf("ListIdPs() returned %d IdPs, want 5", len(idps))
	}

	// Verify IdPs from different nesting levels are found
	expectedIdPs := []string{
		"https://idp.federation.example.org", // top-level
		"https://idp.university-north.edu",   // nested: Universities
		"https://idp.university-south.edu",   // nested: Universities
		"https://idp.research-center.org",    // nested: Research Institutes
		"https://idp.physics-lab.org",        // deeply nested: Research > Labs
	}

	for _, entityID := range expectedIdPs {
		if _, err := store.GetIdP(entityID); err != nil {
			t.Errorf("GetIdP(%q) failed: %v (should be found from nested structure)", entityID, err)
		}
	}

	// Verify SP was skipped
	if _, err := store.GetIdP("https://sp.library.edu"); err != ErrIdPNotFound {
		t.Error("SP entity in nested structure should have been skipped")
	}
}

func TestFileMetadataStore_Refresh_Aggregate(t *testing.T) {
	// Test that Refresh() works correctly with aggregate metadata
	dir := t.TempDir()
	path := filepath.Join(dir, "federation.xml")

	// Write initial aggregate with 2 IdPs
	initialXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://idp1.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
        </IDPSSODescriptor>
        <Organization><OrganizationDisplayName xml:lang="en">First IdP</OrganizationDisplayName></Organization>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://idp2.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/>
        </IDPSSODescriptor>
        <Organization><OrganizationDisplayName xml:lang="en">Second IdP</OrganizationDisplayName></Organization>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(initialXML), 0644); err != nil {
		t.Fatalf("write initial metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify initial state
	idps, _ := store.ListIdPs("")
	if len(idps) != 2 {
		t.Fatalf("initial load: got %d IdPs, want 2", len(idps))
	}

	// Update file: remove one IdP, add a new one
	updatedXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://idp1.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
        </IDPSSODescriptor>
        <Organization><OrganizationDisplayName xml:lang="en">First IdP</OrganizationDisplayName></Organization>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://idp3.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp3.example.com/sso"/>
        </IDPSSODescriptor>
        <Organization><OrganizationDisplayName xml:lang="en">Third IdP</OrganizationDisplayName></Organization>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(updatedXML), 0644); err != nil {
		t.Fatalf("write updated metadata: %v", err)
	}

	// Refresh
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Verify updated state
	idps, _ = store.ListIdPs("")
	if len(idps) != 2 {
		t.Errorf("after refresh: got %d IdPs, want 2", len(idps))
	}

	// idp2 should be gone, idp3 should be present
	if _, err := store.GetIdP("https://idp2.example.com"); err != ErrIdPNotFound {
		t.Error("idp2 should not be found after refresh")
	}
	if _, err := store.GetIdP("https://idp3.example.com"); err != nil {
		t.Error("idp3 should be found after refresh")
	}
}

// URLMetadataStore tests

func TestURLMetadataStore_Load(t *testing.T) {
	// Serve testdata/idp-metadata.xml via httptest.Server
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP, got %d", len(idps))
	}

	idp := idps[0]

	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("EntityID = %q, want %q", idp.EntityID, "https://idp.example.com/saml")
	}

	if idp.DisplayName != "Example IdP" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Example IdP")
	}

	if idp.SSOURL != "https://idp.example.com/saml/sso" {
		t.Errorf("SSOURL = %q, want %q", idp.SSOURL, "https://idp.example.com/saml/sso")
	}
}

func TestURLMetadataStore_GetIdP(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Found
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.EntityID != "https://idp.example.com/saml" {
		t.Errorf("wrong EntityID returned")
	}

	// Not found
	_, err = store.GetIdP("https://unknown.example.com")
	if err != ErrIdPNotFound {
		t.Errorf("expected ErrIdPNotFound, got %v", err)
	}
}

func TestURLMetadataStore_Load_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			store := NewURLMetadataStore(server.URL, time.Hour)
			err := store.Load()
			if err == nil {
				t.Error("expected error for HTTP error response")
			}
		})
	}
}

func TestURLMetadataStore_Load_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid xml"))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestURLMetadataStore_Load_NetworkError(t *testing.T) {
	// Use a URL that will fail to connect
	store := NewURLMetadataStore("http://localhost:1", time.Hour)
	err := store.Load()
	if err == nil {
		t.Error("expected error for network failure")
	}
}

func TestURLMetadataStore_Load_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second) // Slow response
		w.Write([]byte("<xml/>"))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := store.Refresh(ctx)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestURLMetadataStore_CacheHit(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Second call within TTL should not fetch again
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch (cache hit), got %d", fetchCount)
	}
}

func TestURLMetadataStore_CacheExpiry(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second call after TTL should fetch again
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches (cache miss), got %d", fetchCount)
	}
}

func TestURLMetadataStore_ConditionalRequest_ETag(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	etag := `"abc123"`
	requestCount := 0
	conditionalRequestReceived := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Check if client sent If-None-Match header
		if r.Header.Get("If-None-Match") == etag {
			conditionalRequestReceived = true
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch - should get full response with ETag
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should send If-None-Match and get 304
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Verify conditional request was sent
	if !conditionalRequestReceived {
		t.Error("expected If-None-Match header to be sent on second request")
	}

	// Data should still be present (not cleared on 304)
	idps, _ = store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after 304 response, got %d", len(idps))
	}
}

func TestURLMetadataStore_ConditionalRequest_LastModified(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	lastMod := "Wed, 01 Jan 2025 00:00:00 GMT"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if client sent If-Modified-Since header
		if r.Header.Get("If-Modified-Since") == lastMod {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lastMod)
		w.Write(metadata)
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should send If-Modified-Since and get 304
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Data should still be present
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after 304 response, got %d", len(idps))
	}
}

func TestURLMetadataStore_ConditionalRequest_Modified(t *testing.T) {
	// First metadata - single IdP
	metadata1, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	// Second metadata - aggregate with 3 IdPs
	metadata2, err := os.ReadFile("testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read aggregate metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("ETag", `"v1"`)
			w.Write(metadata1)
		} else {
			// New version - different ETag, return full response
			w.Header().Set("ETag", `"v2"`)
			w.Write(metadata2)
		}
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First fetch - single IdP
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second fetch - should get updated data
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	idps, _ = store.ListIdPs("")
	if len(idps) != 3 {
		t.Errorf("expected 3 IdPs after update, got %d", len(idps))
	}
}

func TestURLMetadataStore_Load_Aggregate(t *testing.T) {
	metadata, err := os.ReadFile("testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3", len(idps))
	}
}

func TestURLMetadataStore_Load_DFNAAISample(t *testing.T) {
	metadata, err := os.ReadFile("testdata/dfn-aai-sample.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// 6 IdPs from DFN-AAI sample (SP should be skipped)
	if len(idps) != 6 {
		t.Errorf("ListIdPs() returned %d IdPs, want 6", len(idps))
	}

	// Verify specific IdP
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if idp.DisplayName != "Freie Universität Berlin" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Freie Universität Berlin")
	}
}

func TestURLMetadataStore_UserAgent(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var receivedUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserAgent = r.Header.Get("User-Agent")
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify User-Agent header was sent
	expectedUserAgent := "caddy-saml-disco/" + Version
	if receivedUserAgent != expectedUserAgent {
		t.Errorf("User-Agent = %q, want %q", receivedUserAgent, expectedUserAgent)
	}
}

// IdP filter pattern tests (provisioning-time filtering)

func TestMatchesEntityIDPattern(t *testing.T) {
	tests := []struct {
		entityID string
		pattern  string
		expected bool
	}{
		// Empty pattern matches everything
		{"https://idp.example.com/saml", "", true},
		{"https://idp.stanford.edu/idp", "", true},

		// Wildcard matches everything
		{"https://idp.example.com/saml", "*", true},
		{"https://idp.stanford.edu/idp", "*", true},

		// Suffix patterns (common use case: filter by domain)
		{"https://idp.example.edu/shibboleth", "*example.edu*", true},
		{"https://idp.stanford.edu/idp", "*stanford.edu*", true},
		{"https://idp.mit.edu/shibboleth", "*stanford.edu*", false},

		// Prefix patterns
		{"https://idp.example.com/saml", "https://idp.example.com*", true},
		{"https://idp.other.com/saml", "https://idp.example.com*", false},

		// Substring patterns (institution name in URL)
		{"https://login.rz.rwth-aachen.de/shibboleth", "*rwth*", true},
		{"https://login.rz.rwth-aachen.de/shibboleth", "*munich*", false},

		// Case sensitivity (entity IDs are case-sensitive per SAML spec)
		{"https://idp.EXAMPLE.com/saml", "*example*", false},
		{"https://idp.EXAMPLE.com/saml", "*EXAMPLE*", true},

		// Pattern with special characters
		{"https://idp.uni-freiburg.de/idp", "*uni-freiburg*", true},

		// No match
		{"https://idp.example.com/saml", "*nonexistent*", false},
	}

	for _, tc := range tests {
		result := matchesEntityIDPattern(tc.entityID, tc.pattern)
		if result != tc.expected {
			t.Errorf("matchesEntityIDPattern(%q, %q) = %v, want %v",
				tc.entityID, tc.pattern, result, tc.expected)
		}
	}
}

func TestFileMetadataStore_WithIdPFilter(t *testing.T) {
	// Load aggregate metadata with filter
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml", WithIdPFilter("*idp1*"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Only idp1.example.com should match the filter
	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}

	if len(idps) > 0 && idps[0].EntityID != "https://idp1.example.com/saml" {
		t.Errorf("Expected idp1.example.com, got %s", idps[0].EntityID)
	}

	// Filtered IdPs should not be accessible via GetIdP
	_, err = store.GetIdP("https://idp2.example.com/saml")
	if err != ErrIdPNotFound {
		t.Error("Filtered IdP should not be accessible via GetIdP")
	}
}

func TestFileMetadataStore_WithIdPFilter_NoMatch(t *testing.T) {
	// Filter that matches nothing
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml", WithIdPFilter("*nonexistent*"))
	err := store.Load()

	// Should fail because no IdPs match
	if err == nil {
		t.Error("Expected error when no IdPs match filter")
	}
}

func TestFileMetadataStore_WithIdPFilter_Empty(t *testing.T) {
	// Empty filter should load all IdPs (same as no filter)
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml", WithIdPFilter(""))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3", len(idps))
	}
}

func TestFileMetadataStore_WithIdPFilter_DFNAAISample(t *testing.T) {
	// Filter for Berlin institutions only
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml", WithIdPFilter("*berlin*"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Only FU Berlin should match (https://identity.fu-berlin.de/idp-fub)
	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}
}

func TestFileMetadataStore_WithIdPFilter_Refresh(t *testing.T) {
	// Test that filter is applied on refresh too
	dir := t.TempDir()
	path := filepath.Join(dir, "federation.xml")

	// Write initial aggregate with 2 IdPs
	initialXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://allowed.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://allowed.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://blocked.other.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://blocked.other.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(initialXML), 0644); err != nil {
		t.Fatalf("write initial metadata: %v", err)
	}

	store := NewFileMetadataStore(path, WithIdPFilter("*example.com*"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Only allowed.example.com should be loaded
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after filtered load, got %d", len(idps))
	}

	// Update file: add another matching IdP
	updatedXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://allowed.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://allowed.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://also-allowed.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://also-allowed.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://still-blocked.other.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://still-blocked.other.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(updatedXML), 0644); err != nil {
		t.Fatalf("write updated metadata: %v", err)
	}

	// Refresh
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Now 2 IdPs should match the filter
	idps, _ = store.ListIdPs("")
	if len(idps) != 2 {
		t.Errorf("expected 2 IdPs after refresh, got %d", len(idps))
	}

	// Verify blocked IdP is still not accessible
	_, err := store.GetIdP("https://still-blocked.other.com")
	if err != ErrIdPNotFound {
		t.Error("Blocked IdP should not be accessible after refresh")
	}
}

func TestURLMetadataStore_WithIdPFilter(t *testing.T) {
	metadata, err := os.ReadFile("testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	// Filter to only load idp2
	store := NewURLMetadataStore(server.URL, time.Hour, WithIdPFilter("*idp2*"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}

	if len(idps) > 0 && idps[0].EntityID != "https://idp2.example.com/saml" {
		t.Errorf("Expected idp2.example.com, got %s", idps[0].EntityID)
	}
}

func TestURLMetadataStore_ListIdPs_Filter(t *testing.T) {
	metadata, err := os.ReadFile("testdata/aggregate-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	tests := []struct {
		filter   string
		expected int
	}{
		{"", 3},           // no filter - all 3 IdPs
		{"University", 2}, // matches State University and Tech University
		{"Corporate", 1},  // matches Corporate Provider only
		{"unknown", 0},    // no match
	}

	for _, tc := range tests {
		idps, err := store.ListIdPs(tc.filter)
		if err != nil {
			t.Errorf("ListIdPs(%q) failed: %v", tc.filter, err)
			continue
		}
		if len(idps) != tc.expected {
			t.Errorf("ListIdPs(%q) returned %d IdPs, want %d", tc.filter, len(idps), tc.expected)
		}
	}
}

// =============================================================================
// mdui:UIInfo Parsing Tests (Phase 2)
// =============================================================================

// TestParseIdP_UIInfo_DisplayName verifies that mdui:DisplayName is preferred
// over Organization/OrganizationDisplayName.
func TestParseIdP_UIInfo_DisplayName(t *testing.T) {
	// DFN-AAI sample has both mdui:DisplayName and OrganizationDisplayName
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// FU Berlin has mdui:DisplayName in both German and English
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should use mdui:DisplayName (prefer English if available)
	// The English mdui:DisplayName is "Freie Universität Berlin"
	if idp.DisplayName != "Freie Universität Berlin" {
		t.Errorf("DisplayName = %q, want %q (from mdui:DisplayName)",
			idp.DisplayName, "Freie Universität Berlin")
	}
}

// TestParseIdP_UIInfo_Description verifies that mdui:Description is extracted.
func TestParseIdP_UIInfo_Description(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// FU Berlin has mdui:Description in both German and English
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should have description (prefer English)
	expectedDesc := "Freie Universität Berlin is one of the leading research universities in Germany."
	if idp.Description != expectedDesc {
		t.Errorf("Description = %q, want %q", idp.Description, expectedDesc)
	}
}

// TestParseIdP_UIInfo_Logo verifies that mdui:Logo URL is extracted.
func TestParseIdP_UIInfo_Logo(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// FU Berlin has mdui:Logo
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should have logo URL (prefer larger logo)
	expectedLogo := "https://www.fu-berlin.de/assets/img/fu-logo.png"
	if idp.LogoURL != expectedLogo {
		t.Errorf("LogoURL = %q, want %q", idp.LogoURL, expectedLogo)
	}
}

// TestParseIdP_UIInfo_InformationURL verifies that mdui:InformationURL is extracted.
func TestParseIdP_UIInfo_InformationURL(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// FU Berlin has mdui:InformationURL in both German and English
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should have information URL (prefer English)
	expectedURL := "https://www.fu-berlin.de/en/"
	if idp.InformationURL != expectedURL {
		t.Errorf("InformationURL = %q, want %q", idp.InformationURL, expectedURL)
	}
}

// TestParseIdP_UIInfo_FallbackToOrganization verifies that Organization is used
// as fallback when mdui:DisplayName is not present.
func TestParseIdP_UIInfo_FallbackToOrganization(t *testing.T) {
	// Create metadata without mdui:UIInfo
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should fall back to OrganizationDisplayName
	if idp.DisplayName != "Example IdP" {
		t.Errorf("DisplayName = %q, want %q (from Organization)", idp.DisplayName, "Example IdP")
	}
}

// TestParseIdP_UIInfo_MinimalEntry verifies parsing works for IdPs with minimal mdui.
func TestParseIdP_UIInfo_MinimalEntry(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// University of Freiburg has minimal mdui (only German DisplayName)
	idp, err := store.GetIdP("https://mylogin.uni-freiburg.de/shibboleth")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should have display name from mdui (only German available)
	if idp.DisplayName != "Albert-Ludwigs-Universität Freiburg" {
		t.Errorf("DisplayName = %q, want %q", idp.DisplayName, "Albert-Ludwigs-Universität Freiburg")
	}

	// Description, Logo, InformationURL should be empty (not present in metadata)
	if idp.Description != "" {
		t.Errorf("Description = %q, want empty string (not in metadata)", idp.Description)
	}
}

// =============================================================================
// Multi-Language Support Tests (Phase 3)
// =============================================================================

// TestIdPInfo_StoresAllLanguageVariants verifies that IdPInfo stores all
// language variants of display names, descriptions, and information URLs.
func TestIdPInfo_StoresAllLanguageVariants(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// TUM has different English and German display names
	idp, err := store.GetIdP("https://tumidp.lrz.de/idp/shibboleth")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// DisplayNames map should exist and contain both languages
	if idp.DisplayNames == nil {
		t.Fatal("DisplayNames map should not be nil")
	}

	if idp.DisplayNames["en"] != "Technical University of Munich (TUM)" {
		t.Errorf("DisplayNames[en] = %q, want %q",
			idp.DisplayNames["en"], "Technical University of Munich (TUM)")
	}
	if idp.DisplayNames["de"] != "Technische Universität München (TUM)" {
		t.Errorf("DisplayNames[de] = %q, want %q",
			idp.DisplayNames["de"], "Technische Universität München (TUM)")
	}

	// Descriptions map should exist and contain both languages
	if idp.Descriptions == nil {
		t.Fatal("Descriptions map should not be nil")
	}

	if idp.Descriptions["en"] != "TUM is one of Europe's leading technical universities, combining top-class facilities for cutting-edge research." {
		t.Errorf("Descriptions[en] = %q, want TUM description", idp.Descriptions["en"])
	}
	if idp.Descriptions["de"] != "Die TUM ist eine der führenden technischen Universitäten Europas." {
		t.Errorf("Descriptions[de] = %q, want German TUM description", idp.Descriptions["de"])
	}

	// InformationURLs map should exist (TUM only has English)
	if idp.InformationURLs == nil {
		t.Fatal("InformationURLs map should not be nil")
	}
	if idp.InformationURLs["en"] != "https://www.tum.de/en/" {
		t.Errorf("InformationURLs[en] = %q, want %q",
			idp.InformationURLs["en"], "https://www.tum.de/en/")
	}
}

// TestSelectFromMap verifies language selection from a map based on preferences.
func TestSelectFromMap(t *testing.T) {
	m := map[string]string{
		"en": "English",
		"de": "Deutsch",
		"fr": "Français",
	}

	tests := []struct {
		name     string
		prefs    []string
		expected string
	}{
		// Direct match
		{"direct match de", []string{"de"}, "Deutsch"},
		{"direct match en", []string{"en"}, "English"},
		{"direct match fr", []string{"fr"}, "Français"},

		// Fallback to second preference
		{"fallback to second", []string{"es", "de"}, "Deutsch"},
		{"fallback to third", []string{"it", "es", "fr"}, "Français"},

		// Regional variant matches base language
		{"regional de-AT", []string{"de-AT"}, "Deutsch"},
		{"regional en-GB", []string{"en-GB"}, "English"},
		{"regional fr-CA", []string{"fr-CA"}, "Français"},

		// Fallback to English when no match
		{"fallback to English", []string{"es", "it"}, "English"},

		// Empty preferences falls back to English
		{"empty prefs", []string{}, "English"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := selectFromMap(m, tc.prefs, "en")
			if result != tc.expected {
				t.Errorf("selectFromMap(m, %v, \"en\") = %q, want %q",
					tc.prefs, result, tc.expected)
			}
		})
	}
}

// TestSelectFromMap_NoEnglish verifies fallback behavior when English is not available.
func TestSelectFromMap_NoEnglish(t *testing.T) {
	m := map[string]string{
		"de": "Deutsch",
		"fr": "Français",
	}

	// No English, no match - should return any available value
	result := selectFromMap(m, []string{"es", "it"}, "en")
	// Result should be one of the available values
	if result != "Deutsch" && result != "Français" {
		t.Errorf("selectFromMap should return any available value, got %q", result)
	}
}

// TestSelectFromMap_Empty verifies handling of empty map.
func TestSelectFromMap_Empty(t *testing.T) {
	m := map[string]string{}
	result := selectFromMap(m, []string{"en"}, "en")
	if result != "" {
		t.Errorf("selectFromMap on empty map = %q, want empty string", result)
	}
}

// TestSelectFromMap_ConfigurableDefault verifies that the default language
// can be configured instead of being hard-coded to English.
func TestSelectFromMap_ConfigurableDefault(t *testing.T) {
	// Map without English - only German and French
	m := map[string]string{
		"de": "Deutsch",
		"fr": "Français",
	}

	tests := []struct {
		name        string
		prefs       []string
		defaultLang string
		expected    string
	}{
		// Default language is used when no preference matches
		{"default de, no match", []string{"es"}, "de", "Deutsch"},
		{"default fr, no match", []string{"es"}, "fr", "Français"},

		// Empty prefs uses default language
		{"empty prefs, default de", []string{}, "de", "Deutsch"},
		{"empty prefs, default fr", []string{}, "fr", "Français"},

		// Preference still takes priority over default
		{"pref matches, ignores default", []string{"fr"}, "de", "Français"},

		// Default not in map falls back to any available
		{"default not available", []string{"es"}, "it", "Deutsch"}, // or Français, just any
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := selectFromMap(m, tc.prefs, tc.defaultLang)
			if tc.name == "default not available" {
				// Special case: result should be any available value
				if result != "Deutsch" && result != "Français" {
					t.Errorf("selectFromMap should return any available value, got %q", result)
				}
				return
			}
			if result != tc.expected {
				t.Errorf("selectFromMap(m, %v, %q) = %q, want %q",
					tc.prefs, tc.defaultLang, result, tc.expected)
			}
		})
	}
}

// TestLocalizeIdPInfo verifies that IdPInfo is correctly localized based on
// language preferences.
func TestLocalizeIdPInfo(t *testing.T) {
	idp := IdPInfo{
		EntityID:    "https://example.com/idp",
		DisplayName: "English Name", // Default (for backward compat)
		DisplayNames: map[string]string{
			"en": "English Name",
			"de": "Deutscher Name",
			"fr": "Nom Français",
		},
		Description: "English description",
		Descriptions: map[string]string{
			"en": "English description",
			"de": "Deutsche Beschreibung",
		},
		InformationURL: "https://example.com/en/",
		InformationURLs: map[string]string{
			"en": "https://example.com/en/",
			"de": "https://example.com/de/",
		},
		LogoURL:    "https://example.com/logo.png",
		SSOURL:     "https://example.com/sso",
		SSOBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
	}

	tests := []struct {
		name            string
		prefs           []string
		expectedName    string
		expectedDesc    string
		expectedInfoURL string
	}{
		{"german", []string{"de"}, "Deutscher Name", "Deutsche Beschreibung", "https://example.com/de/"},
		{"french name only", []string{"fr"}, "Nom Français", "English description", "https://example.com/en/"}, // fr desc not available
		{"fallback to german", []string{"es", "de"}, "Deutscher Name", "Deutsche Beschreibung", "https://example.com/de/"},
		{"empty prefs", []string{}, "English Name", "English description", "https://example.com/en/"},
		{"regional de-AT", []string{"de-AT"}, "Deutscher Name", "Deutsche Beschreibung", "https://example.com/de/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			localized := LocalizeIdPInfo(idp, tc.prefs, "en")

			if localized.DisplayName != tc.expectedName {
				t.Errorf("DisplayName = %q, want %q", localized.DisplayName, tc.expectedName)
			}
			if localized.Description != tc.expectedDesc {
				t.Errorf("Description = %q, want %q", localized.Description, tc.expectedDesc)
			}
			if localized.InformationURL != tc.expectedInfoURL {
				t.Errorf("InformationURL = %q, want %q", localized.InformationURL, tc.expectedInfoURL)
			}

			// Non-localized fields should remain unchanged
			if localized.EntityID != idp.EntityID {
				t.Errorf("EntityID changed: %q != %q", localized.EntityID, idp.EntityID)
			}
			if localized.LogoURL != idp.LogoURL {
				t.Errorf("LogoURL changed: %q != %q", localized.LogoURL, idp.LogoURL)
			}
			if localized.SSOURL != idp.SSOURL {
				t.Errorf("SSOURL changed: %q != %q", localized.SSOURL, idp.SSOURL)
			}
		})
	}
}

// TestLocalizeIdPInfo_EmptyMaps verifies backward compatibility when
// language maps are empty (uses original single-value fields).
func TestLocalizeIdPInfo_EmptyMaps(t *testing.T) {
	idp := IdPInfo{
		EntityID:       "https://example.com/idp",
		DisplayName:    "Original Name",
		Description:    "Original Description",
		InformationURL: "https://example.com/",
	}

	localized := LocalizeIdPInfo(idp, []string{"de"}, "en")

	// Should preserve original values when maps are empty
	if localized.DisplayName != "Original Name" {
		t.Errorf("DisplayName = %q, want %q", localized.DisplayName, "Original Name")
	}
	if localized.Description != "Original Description" {
		t.Errorf("Description = %q, want %q", localized.Description, "Original Description")
	}
	if localized.InformationURL != "https://example.com/" {
		t.Errorf("InformationURL = %q, want %q", localized.InformationURL, "https://example.com/")
	}
}

// TestLocalizeIdPInfo_ConfigurableDefault verifies that the configured
// default language is used when no Accept-Language preference matches.
func TestLocalizeIdPInfo_ConfigurableDefault(t *testing.T) {
	// IdP with only German and French - no English
	idp := IdPInfo{
		EntityID:    "https://example.com/idp",
		DisplayName: "Fallback Name", // Would be set during metadata parsing
		DisplayNames: map[string]string{
			"de": "Deutscher Name",
			"fr": "Nom Français",
		},
		Description: "Fallback Description",
		Descriptions: map[string]string{
			"de": "Deutsche Beschreibung",
			"fr": "Description Française",
		},
	}

	tests := []struct {
		name         string
		prefs        []string
		defaultLang  string
		expectedName string
		expectedDesc string
	}{
		// Default to German when no preference matches
		{"no match, default de", []string{"es"}, "de", "Deutscher Name", "Deutsche Beschreibung"},
		// Default to French when no preference matches
		{"no match, default fr", []string{"es"}, "fr", "Nom Français", "Description Française"},
		// Empty preferences use default
		{"empty prefs, default de", []string{}, "de", "Deutscher Name", "Deutsche Beschreibung"},
		// Preference takes priority over default
		{"pref fr, default de", []string{"fr"}, "de", "Nom Français", "Description Française"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			localized := LocalizeIdPInfo(idp, tc.prefs, tc.defaultLang)

			if localized.DisplayName != tc.expectedName {
				t.Errorf("DisplayName = %q, want %q", localized.DisplayName, tc.expectedName)
			}
			if localized.Description != tc.expectedDesc {
				t.Errorf("Description = %q, want %q", localized.Description, tc.expectedDesc)
			}
		})
	}
}

// =============================================================================
// Multi-Language Search Tests (Phase 3)
// =============================================================================

// TestMatchesSearch_AllLanguageVariants verifies that search matches against
// ALL language variants of DisplayNames, not just the default DisplayName.
func TestMatchesSearch_AllLanguageVariants(t *testing.T) {
	idp := IdPInfo{
		EntityID:    "https://tum.de/idp",
		DisplayName: "Technical University of Munich",
		DisplayNames: map[string]string{
			"en": "Technical University of Munich",
			"de": "Technische Universität München",
		},
	}

	tests := []struct {
		query    string
		expected bool
	}{
		// Empty query matches all
		{"", true},

		// English name matches
		{"Munich", true},
		{"Technical", true},
		{"university", true}, // case insensitive

		// German name matches (NEW BEHAVIOR!)
		{"München", true},
		{"Technische", true},
		{"Universität", true},

		// EntityID matches
		{"tum.de", true},

		// No match
		{"Harvard", false},
		{"Stanford", false},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			result := MatchesSearch(&idp, tc.query)
			if result != tc.expected {
				t.Errorf("MatchesSearch(%q) = %v, want %v", tc.query, result, tc.expected)
			}
		})
	}
}

// TestMatchesSearch_EmptyDisplayNames verifies backward compatibility when
// DisplayNames map is nil (uses only DisplayName field).
func TestMatchesSearch_EmptyDisplayNames(t *testing.T) {
	idp := IdPInfo{
		EntityID:    "https://example.com/idp",
		DisplayName: "Example University",
		// DisplayNames is nil
	}

	tests := []struct {
		query    string
		expected bool
	}{
		{"Example", true},
		{"University", true},
		{"example.com", true},
		{"Unknown", false},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			result := MatchesSearch(&idp, tc.query)
			if result != tc.expected {
				t.Errorf("MatchesSearch(%q) = %v, want %v", tc.query, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// mdrpi:RegistrationInfo Parsing Tests (Phase 4)
// =============================================================================

// TestParseIdP_RegistrationInfo_Authority verifies that mdrpi:RegistrationInfo
// registrationAuthority attribute is parsed.
func TestParseIdP_RegistrationInfo_Authority(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	expected := "https://www.aai.dfn.de"
	if idp.RegistrationAuthority != expected {
		t.Errorf("RegistrationAuthority = %q, want %q", idp.RegistrationAuthority, expected)
	}
}

// TestParseIdP_RegistrationInfo_Instant verifies that mdrpi:RegistrationInfo
// registrationInstant attribute is parsed.
func TestParseIdP_RegistrationInfo_Instant(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	expected := time.Date(2010, 3, 15, 10, 0, 0, 0, time.UTC)
	if !idp.RegistrationInstant.Equal(expected) {
		t.Errorf("RegistrationInstant = %v, want %v", idp.RegistrationInstant, expected)
	}
}

// TestParseIdP_RegistrationInfo_Policies verifies that mdrpi:RegistrationPolicy
// elements are parsed into a language map.
func TestParseIdP_RegistrationInfo_Policies(t *testing.T) {
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	if idp.RegistrationPolicies == nil {
		t.Fatal("RegistrationPolicies should not be nil")
	}

	if idp.RegistrationPolicies["en"] != "https://www.aai.dfn.de/en/join/" {
		t.Errorf("RegistrationPolicies[en] = %q, want policy URL", idp.RegistrationPolicies["en"])
	}
	if idp.RegistrationPolicies["de"] != "https://www.aai.dfn.de/teilnahme/" {
		t.Errorf("RegistrationPolicies[de] = %q, want policy URL", idp.RegistrationPolicies["de"])
	}
}

// TestParseIdP_NoRegistrationInfo verifies graceful handling of IdPs without
// mdrpi:RegistrationInfo (should have zero/empty values, not panic).
func TestParseIdP_NoRegistrationInfo(t *testing.T) {
	// idp-metadata.xml has no mdrpi:RegistrationInfo
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}

	// Should be empty/zero values, not panic
	if idp.RegistrationAuthority != "" {
		t.Errorf("RegistrationAuthority should be empty, got %q", idp.RegistrationAuthority)
	}
	if !idp.RegistrationInstant.IsZero() {
		t.Errorf("RegistrationInstant should be zero, got %v", idp.RegistrationInstant)
	}
	if idp.RegistrationPolicies != nil {
		t.Errorf("RegistrationPolicies should be nil, got %v", idp.RegistrationPolicies)
	}
}

// =============================================================================
// Graceful Degradation Tests (serve stale metadata on fetch failure)
// =============================================================================

// TestURLMetadataStore_IsFresh_InitiallyFalse verifies that a new store
// reports IsFresh() = false before any successful load.
func TestURLMetadataStore_IsFresh_InitiallyFalse(t *testing.T) {
	store := NewURLMetadataStore("http://localhost:1", time.Hour)

	if store.IsFresh() {
		t.Error("IsFresh() should be false before any load")
	}
}

// TestURLMetadataStore_IsFresh_AfterSuccessfulLoad verifies that IsFresh()
// returns true after a successful load.
func TestURLMetadataStore_IsFresh_AfterSuccessfulLoad(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !store.IsFresh() {
		t.Error("IsFresh() should be true after successful load")
	}
}

// TestURLMetadataStore_Refresh_PreservesDataOnFailure verifies that when
// Refresh() fails, the existing cached data is preserved and IsFresh() becomes false.
func TestURLMetadataStore_Refresh_PreservesDataOnFailure(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// First request succeeds
			w.Write(metadata)
		} else {
			// Subsequent requests fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	// Use fake clock to control cache expiration without time.Sleep
	fakeClock := NewFakeClock()
	store := NewURLMetadataStore(server.URL, 10*time.Second, WithClock(fakeClock))

	// First load succeeds
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify data loaded and fresh
	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after initial load, got %d", len(idps))
	}
	if !store.IsFresh() {
		t.Fatal("IsFresh() should be true after successful load")
	}

	// Advance clock past TTL (no time.Sleep)
	fakeClock.Advance(11 * time.Second)

	// Second refresh fails (server returns 500)
	err = store.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() should return error on HTTP 500")
	}

	// Data should still be present (graceful degradation)
	idps, _ = store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP after failed refresh (stale data), got %d", len(idps))
	}

	// But IsFresh() should now be false
	if store.IsFresh() {
		t.Error("IsFresh() should be false after failed refresh")
	}

	// GetIdP should still work with stale data
	idp, err := store.GetIdP("https://idp.example.com/saml")
	if err != nil {
		t.Errorf("GetIdP() should work with stale data: %v", err)
	}
	if idp == nil {
		t.Error("GetIdP() returned nil with stale data")
	}
}

// TestURLMetadataStore_LastError_ReturnsNilOnSuccess verifies that LastError()
// returns nil after a successful refresh.
func TestURLMetadataStore_LastError_ReturnsNilOnSuccess(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if store.LastError() != nil {
		t.Errorf("LastError() should be nil after success, got %v", store.LastError())
	}
}

// TestURLMetadataStore_LastError_ReturnsErrorOnFailure verifies that LastError()
// returns the error from the last failed refresh.
func TestURLMetadataStore_LastError_ReturnsErrorOnFailure(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Write(metadata)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First load succeeds
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if store.LastError() != nil {
		t.Errorf("LastError() should be nil after success")
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Second refresh fails
	_ = store.Refresh(context.Background())

	// LastError should now be set
	if store.LastError() == nil {
		t.Error("LastError() should return error after failed refresh")
	}
}

// TestURLMetadataStore_Health_ReturnsStatus verifies that Health() returns
// comprehensive status information.
func TestURLMetadataStore_Health_ReturnsStatus(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Write(metadata)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// Before load: empty health
	health := store.Health()
	if health.IsFresh {
		t.Error("Health.IsFresh should be false before load")
	}
	if health.IdPCount != 0 {
		t.Errorf("Health.IdPCount should be 0 before load, got %d", health.IdPCount)
	}

	// After successful load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health = store.Health()
	if !health.IsFresh {
		t.Error("Health.IsFresh should be true after successful load")
	}
	if health.IdPCount != 1 {
		t.Errorf("Health.IdPCount should be 1, got %d", health.IdPCount)
	}
	if health.LastSuccessTime.IsZero() {
		t.Error("Health.LastSuccessTime should be set")
	}
	if health.LastError != nil {
		t.Errorf("Health.LastError should be nil, got %v", health.LastError)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// After failed refresh
	_ = store.Refresh(context.Background())

	health = store.Health()
	if health.IsFresh {
		t.Error("Health.IsFresh should be false after failed refresh")
	}
	if health.IdPCount != 1 {
		t.Errorf("Health.IdPCount should still be 1 (stale data), got %d", health.IdPCount)
	}
	if health.LastError == nil {
		t.Error("Health.LastError should be set after failed refresh")
	}
	// LastSuccessTime should still reflect the last successful load
	if health.LastSuccessTime.IsZero() {
		t.Error("Health.LastSuccessTime should still be set from previous success")
	}
}

func TestInMemoryMetadataStore_Health(t *testing.T) {
	store := NewInMemoryMetadataStore([]IdPInfo{
		{EntityID: "https://idp1.example.com"},
		{EntityID: "https://idp2.example.com"},
	})

	health := store.Health()

	if !health.IsFresh {
		t.Error("in-memory store should always be fresh")
	}
	if health.IdPCount != 2 {
		t.Errorf("expected 2 IdPs, got %d", health.IdPCount)
	}
	if health.LastError != nil {
		t.Errorf("expected nil LastError, got %v", health.LastError)
	}
}

func TestFileMetadataStore_Health_BeforeLoad(t *testing.T) {
	store := NewFileMetadataStore("/nonexistent.xml")
	health := store.Health()

	if health.IsFresh {
		t.Error("unloaded store should not be fresh")
	}
	if health.IdPCount != 0 {
		t.Errorf("expected 0 IdPs, got %d", health.IdPCount)
	}
}

func TestFileMetadataStore_Health_AfterLoad(t *testing.T) {
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if !health.IsFresh {
		t.Error("loaded store should be fresh")
	}
	if health.IdPCount == 0 {
		t.Error("expected IdPs after load")
	}
}

// =============================================================================
// Metadata validUntil Validation Tests (Phase 4)
// =============================================================================

// TestIsMetadataExpired verifies the pure validation function.
func TestIsMetadataExpired(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		validUntil time.Time
		expected   bool
	}{
		// Zero time means no expiry - not expired
		{"zero time (no expiry)", time.Time{}, false},

		// Future validUntil - not expired
		{"future date", time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), false},
		{"far future", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), false},

		// Past validUntil - expired
		{"past date", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"yesterday", time.Date(2025, 1, 14, 0, 0, 0, 0, time.UTC), true},

		// Edge case: exactly now - expired (not before)
		{"exactly now", now, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsMetadataExpired(tc.validUntil, now)
			if result != tc.expected {
				t.Errorf("IsMetadataExpired(%v, %v) = %v, want %v",
					tc.validUntil, now, result, tc.expected)
			}
		})
	}
}

// TestFileMetadataStore_Load_ExpiredMetadata verifies that expired metadata
// is rejected during loading.
func TestFileMetadataStore_Load_ExpiredMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expired.xml")

	// Metadata with validUntil in the past
	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(expiredXML), 0644); err != nil {
		t.Fatalf("write expired metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()

	// Should fail because metadata is expired
	if err == nil {
		t.Error("expected error for expired metadata")
	}
	if err != nil && !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

// TestFileMetadataStore_Load_ValidMetadata verifies that metadata with
// future validUntil is accepted.
func TestFileMetadataStore_Load_ValidMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.xml")

	// Metadata with validUntil in the future
	validXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2030-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(validXML), 0644); err != nil {
		t.Fatalf("write valid metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()

	if err != nil {
		t.Errorf("unexpected error for valid metadata: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(idps))
	}
}

// TestFileMetadataStore_Load_NoValidUntil verifies that metadata without
// validUntil attribute is accepted (no expiry).
func TestFileMetadataStore_Load_NoValidUntil(t *testing.T) {
	// testdata/aggregate-metadata.xml has no validUntil - should work
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml")
	err := store.Load()

	if err != nil {
		t.Errorf("unexpected error for metadata without validUntil: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 3 {
		t.Errorf("expected 3 IdPs, got %d", len(idps))
	}
}

// TestFileMetadataStore_Load_SingleEntityExpired verifies that single
// EntityDescriptor (not aggregate) with expired validUntil is rejected.
func TestFileMetadataStore_Load_SingleEntityExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "expired-single.xml")

	expiredXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com"
                  validUntil="2020-01-01T00:00:00Z">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`
	if err := os.WriteFile(path, []byte(expiredXML), 0644); err != nil {
		t.Fatalf("write expired metadata: %v", err)
	}

	store := NewFileMetadataStore(path)
	err := store.Load()

	if err == nil {
		t.Error("expected error for expired single EntityDescriptor")
	}
}

// TestFileMetadataStore_Load_ExpiredMetadata_Logs verifies that expired metadata
// rejection is logged with structured fields.
func TestFileMetadataStore_Load_ExpiredMetadata_Logs(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	dir := t.TempDir()
	path := filepath.Join(dir, "expired.xml")

	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`
	if err := os.WriteFile(path, []byte(expiredXML), 0644); err != nil {
		t.Fatalf("write expired metadata: %v", err)
	}

	store := NewFileMetadataStore(path, WithLogger(logger))
	_ = store.Load() // Expected to fail

	// Assert: warning log with structured fields
	warnLogs := logs.FilterMessage("metadata expired")
	if warnLogs.Len() == 0 {
		t.Error("expected 'metadata expired' warning log")
	}

	if warnLogs.Len() > 0 {
		entry := warnLogs.All()[0]
		fields := entry.ContextMap()

		// Verify structured fields
		if _, ok := fields["source"]; !ok {
			t.Error("expected source field in log")
		}
	}
}

// TestURLMetadataStore_Load_ExpiredMetadata verifies that URL-based loading
// also rejects expired metadata.
func TestURLMetadataStore_Load_ExpiredMetadata(t *testing.T) {
	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expiredXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()

	if err == nil {
		t.Error("expected error for expired metadata from URL")
	}
	if err != nil && !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention 'expired', got: %v", err)
	}
}

// TestURLMetadataStore_Load_ValidMetadata verifies that URL-based loading
// accepts metadata with future validUntil.
func TestURLMetadataStore_Load_ValidMetadataWithValidUntil(t *testing.T) {
	validXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2030-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(validXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour)
	err := store.Load()

	if err != nil {
		t.Errorf("unexpected error for valid metadata: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(idps))
	}
}

// =============================================================================
// Background Refresh Tests (Phase 4)
// =============================================================================

// TestURLMetadataStore_BackgroundRefresh verifies that the store periodically
// fetches metadata when created with NewURLMetadataStoreWithRefresh.
func TestURLMetadataStore_BackgroundRefresh(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load counts as 1
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for exactly 2 background refresh cycles (no time.Sleep)
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first background refresh")
	}
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for second background refresh")
	}

	// Should have made additional requests from background refresh
	mu.Lock()
	count := requestCount
	mu.Unlock()

	// 1 initial + 2 background = 3 minimum
	if count < 3 {
		t.Errorf("expected at least 3 requests (initial + 2 background), got %d", count)
	}
}

// TestURLMetadataStore_Close_StopsBackgroundRefresh verifies that Close()
// stops the background refresh goroutine.
func TestURLMetadataStore_Close_StopsBackgroundRefresh(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	var requestCount int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to detect refresh attempts
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 10*time.Millisecond,
		WithOnRefresh(func(err error) { refreshed <- err }))

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for one background refresh to confirm goroutine is running
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Record count and close
	mu.Lock()
	countAfterClose := requestCount
	mu.Unlock()
	store.Close()

	// After Close(), the channel should not receive more (use short timeout)
	select {
	case <-refreshed:
		t.Error("received refresh after Close()")
	case <-time.After(50 * time.Millisecond):
		// Expected: no refresh after close
	}

	mu.Lock()
	finalCount := requestCount
	mu.Unlock()

	if finalCount != countAfterClose {
		t.Errorf("requests continued after Close(): had %d, now %d", countAfterClose, finalCount)
	}
}

// TestURLMetadataStore_Close_Idempotent verifies that Close() can be called
// multiple times without panicking.
func TestURLMetadataStore_Close_Idempotent(t *testing.T) {
	store := NewURLMetadataStoreWithRefresh("http://example.com", time.Hour)

	// Should not panic when called multiple times
	store.Close()
	store.Close()
	store.Close()
}

// TestURLMetadataStore_Close_NoBackgroundRefresh verifies that Close() works
// on stores created without background refresh (via NewURLMetadataStore).
func TestURLMetadataStore_Close_NoBackgroundRefresh(t *testing.T) {
	store := NewURLMetadataStore("http://example.com", time.Hour)

	// Should not panic - Close() should be a no-op for passive stores
	store.Close()
}

// =============================================================================
// Logger Integration Tests
// =============================================================================

// TestURLMetadataStore_WithLogger verifies that a logger can be injected
// via the WithLogger option.
func TestURLMetadataStore_WithLogger(t *testing.T) {
	core, _ := observer.New(zap.DebugLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))

	if store.logger == nil {
		t.Error("expected logger to be set via WithLogger option")
	}
}

// TestURLMetadataStore_BackgroundRefresh_LogsSuccess verifies that successful
// background refresh events are logged.
func TestURLMetadataStore_BackgroundRefresh_LogsSuccess(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithLogger(logger),
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Initial load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for at least one background refresh cycle
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Assert: at least one success log
	successLogs := logs.FilterMessage("background metadata refresh succeeded")
	if successLogs.Len() == 0 {
		t.Error("expected success log message from background refresh")
	}

	// Verify idp_count field is present
	if successLogs.Len() > 0 {
		entry := successLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in log entry")
		}
	}
}

// TestURLMetadataStore_BackgroundRefresh_LogsFailure verifies that failed
// background refresh events are logged with error details.
func TestURLMetadataStore_BackgroundRefresh_LogsFailure(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Use channel to synchronize on refresh completion
	refreshed := make(chan error, 10)
	store := NewURLMetadataStoreWithRefresh(server.URL, 50*time.Millisecond,
		WithLogger(logger),
		WithOnRefresh(func(err error) { refreshed <- err }))
	defer store.Close()

	// Wait for at least one background refresh cycle (no initial Load needed - will fail)
	select {
	case <-refreshed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for background refresh")
	}

	// Assert: at least one failure log
	failLogs := logs.FilterMessage("background metadata refresh failed")
	if failLogs.Len() == 0 {
		t.Error("expected failure log message from background refresh")
	}

	// Verify error field is present and contains HTTP status
	if failLogs.Len() > 0 {
		entry := failLogs.All()[0]
		fields := entry.ContextMap()
		errVal, ok := fields["error"]
		if !ok {
			t.Error("expected error field in log entry")
		} else if errStr, isStr := errVal.(string); isStr {
			if !strings.Contains(errStr, "500") {
				t.Errorf("expected HTTP 500 in error, got: %s", errStr)
			}
		}
	}
}

// TestURLMetadataStore_Load_ExpiredMetadata_Logs verifies that expired metadata
// rejection from HTTP source is logged with structured fields.
func TestURLMetadataStore_Load_ExpiredMetadata_Logs(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	expiredXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    validUntil="2020-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://idp.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="https://idp.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expiredXML))
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, time.Hour, WithLogger(logger))
	_ = store.Load() // Expected to fail

	// Assert: warning log with structured fields
	warnLogs := logs.FilterMessage("metadata expired")
	if warnLogs.Len() == 0 {
		t.Error("expected 'metadata expired' warning log")
	}

	if warnLogs.Len() > 0 {
		entry := warnLogs.All()[0]
		fields := entry.ContextMap()

		if _, ok := fields["source"]; !ok {
			t.Error("expected source field (URL) in log")
		}
	}
}

// =============================================================================
// MetadataHealth validUntil Tests (Phase 5 - Federation Hardening)
// =============================================================================

func TestURLMetadataStore_Health_ReturnsValidUntil(t *testing.T) {
	// Use dfn-aai-sample.xml which has validUntil="2025-12-31T23:59:59Z"
	metadata, err := os.ReadFile("testdata/dfn-aai-sample.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 1*time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil == nil {
		t.Fatal("Health.MetadataValidUntil should be set for metadata with validUntil")
	}

	expected := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	if !health.MetadataValidUntil.Equal(expected) {
		t.Errorf("MetadataValidUntil = %v, want %v", *health.MetadataValidUntil, expected)
	}
}

func TestURLMetadataStore_Health_NoValidUntil(t *testing.T) {
	// Use idp-metadata.xml which has no validUntil attribute
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metadata)
	}))
	defer server.Close()

	store := NewURLMetadataStore(server.URL, 1*time.Hour)
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil for metadata without validUntil, got %v", *health.MetadataValidUntil)
	}
}

func TestFileMetadataStore_Health_ReturnsValidUntil(t *testing.T) {
	// Use dfn-aai-sample.xml which has validUntil="2025-12-31T23:59:59Z"
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil == nil {
		t.Fatal("Health.MetadataValidUntil should be set for metadata with validUntil")
	}

	expected := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	if !health.MetadataValidUntil.Equal(expected) {
		t.Errorf("MetadataValidUntil = %v, want %v", *health.MetadataValidUntil, expected)
	}
}

func TestFileMetadataStore_Health_NoValidUntil(t *testing.T) {
	// Use idp-metadata.xml which has no validUntil attribute
	store := NewFileMetadataStore("testdata/idp-metadata.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil for metadata without validUntil, got %v", *health.MetadataValidUntil)
	}
}

func TestInMemoryMetadataStore_Health_WithValidUntil(t *testing.T) {
	validUntil := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	store := NewInMemoryMetadataStoreWithValidUntil(
		[]IdPInfo{{EntityID: "https://idp.example.com"}},
		&validUntil,
	)

	health := store.Health()

	if health.MetadataValidUntil == nil {
		t.Fatal("Health.MetadataValidUntil should be set")
	}
	if !health.MetadataValidUntil.Equal(validUntil) {
		t.Errorf("MetadataValidUntil = %v, want %v", *health.MetadataValidUntil, validUntil)
	}
}

func TestInMemoryMetadataStore_Health_WithoutValidUntil(t *testing.T) {
	store := NewInMemoryMetadataStore([]IdPInfo{{EntityID: "https://idp.example.com"}})

	health := store.Health()

	if health.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil, got %v", *health.MetadataValidUntil)
	}
}

// metadataTestMetricsRecorder records metrics calls for testing metadata stores.
type metadataTestMetricsRecorder struct {
	mu           sync.Mutex
	refreshCalls []struct {
		source   string
		success  bool
		idpCount int
	}
}

func (m *metadataTestMetricsRecorder) RecordAuthAttempt(idpEntityID string, success bool) {}
func (m *metadataTestMetricsRecorder) RecordSessionCreated()                              {}
func (m *metadataTestMetricsRecorder) RecordSessionValidation(valid bool)                 {}
func (m *metadataTestMetricsRecorder) RecordMetadataRefresh(source string, success bool, idpCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshCalls = append(m.refreshCalls, struct {
		source   string
		success  bool
		idpCount int
	}{source, success, idpCount})
}

func (m *metadataTestMetricsRecorder) getRefreshCalls() []struct {
	source   string
	success  bool
	idpCount int
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshCalls
}

func TestFileMetadataStore_RecordsMetricsOnSuccess(t *testing.T) {
	mock := &metadataTestMetricsRecorder{}
	store := NewFileMetadataStore("testdata/idp-metadata.xml", WithMetricsRecorder(mock))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	calls := mock.getRefreshCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.source != "file" {
		t.Errorf("source = %q, want %q", call.source, "file")
	}
	if !call.success {
		t.Error("success = false, want true")
	}
	if call.idpCount != 1 {
		t.Errorf("idpCount = %d, want 1", call.idpCount)
	}
}

func TestFileMetadataStore_RecordsMetricsOnFailure(t *testing.T) {
	mock := &metadataTestMetricsRecorder{}
	store := NewFileMetadataStore("/nonexistent/path/metadata.xml", WithMetricsRecorder(mock))

	err := store.Load()
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	calls := mock.getRefreshCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.source != "file" {
		t.Errorf("source = %q, want %q", call.source, "file")
	}
	if call.success {
		t.Error("success = true, want false")
	}
	if call.idpCount != 0 {
		t.Errorf("idpCount = %d, want 0", call.idpCount)
	}
}

func TestURLMetadataStore_RecordsMetricsOnSuccess(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	mock := &metadataTestMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	calls := mock.getRefreshCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.source != "url" {
		t.Errorf("source = %q, want %q", call.source, "url")
	}
	if !call.success {
		t.Error("success = false, want true")
	}
	if call.idpCount != 1 {
		t.Errorf("idpCount = %d, want 1", call.idpCount)
	}
}

func TestURLMetadataStore_RecordsMetricsOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	mock := &metadataTestMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	err := store.Load()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	calls := mock.getRefreshCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.source != "url" {
		t.Errorf("source = %q, want %q", call.source, "url")
	}
	if call.success {
		t.Error("success = true, want false")
	}
	if call.idpCount != 0 {
		t.Errorf("idpCount = %d, want 0", call.idpCount)
	}
}

func TestURLMetadataStore_DoesNotRecordMetricsOnCacheHit(t *testing.T) {
	metadata, err := os.ReadFile("testdata/idp-metadata.xml")
	if err != nil {
		t.Fatalf("read test metadata: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/xml")
		w.Write(metadata)
	}))
	defer server.Close()

	mock := &metadataTestMetricsRecorder{}
	store := NewURLMetadataStore(server.URL, time.Hour, WithMetricsRecorder(mock))

	// First load
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Second load (should be cache hit)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	// Only one HTTP request should have been made
	if requestCount != 1 {
		t.Errorf("expected 1 HTTP request, got %d", requestCount)
	}

	// Only one metrics call (from first load, not from cache hit)
	calls := mock.getRefreshCalls()
	if len(calls) != 1 {
		t.Errorf("expected 1 metrics call (no metrics on cache hit), got %d", len(calls))
	}
}

// TestFilterIdPsByRegistrationAuthority tests the pure domain filter function
func TestFilterIdPsByRegistrationAuthority(t *testing.T) {
	idps := []IdPInfo{
		{EntityID: "https://idp1.example.com", RegistrationAuthority: "https://www.aai.dfn.de"},
		{EntityID: "https://idp2.example.com", RegistrationAuthority: "https://incommon.org"},
		{EntityID: "https://idp3.example.com", RegistrationAuthority: "https://www.aai.dfn.de"},
		{EntityID: "https://idp4.example.com", RegistrationAuthority: ""}, // No registration authority
	}

	tests := []struct {
		name     string
		pattern  string
		expected int
	}{
		// Empty pattern should return all IdPs
		{"empty pattern", "", 4},
		// Exact match
		{"exact match DFN", "https://www.aai.dfn.de", 2},
		{"exact match InCommon", "https://incommon.org", 1},
		// Substring pattern
		{"substring dfn", "*dfn*", 2},
		{"substring incommon", "*incommon*", 1},
		// Prefix pattern
		{"prefix https://www.aai", "https://www.aai*", 2},
		// Suffix pattern
		{"suffix .de", "*.de", 2},
		{"suffix .org", "*.org", 1},
		// No match (IdPs without registration authority are excluded)
		{"no match", "https://nonexistent.org", 0},
		// Comma-separated patterns (multiple federations)
		{"multiple federations", "https://www.aai.dfn.de,https://incommon.org", 3},
		{"multiple with spaces", "https://www.aai.dfn.de, https://incommon.org", 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := filterIdPsByRegistrationAuthority(idps, tc.pattern)
			if len(result) != tc.expected {
				t.Errorf("filterIdPsByRegistrationAuthority(%q) returned %d IdPs, want %d",
					tc.pattern, len(result), tc.expected)
			}
		})
	}
}

// TestFileMetadataStore_WithRegistrationAuthorityFilter tests filtering via FileMetadataStore
func TestFileMetadataStore_WithRegistrationAuthorityFilter(t *testing.T) {
	// dfn-aai-sample.xml contains IdPs registered by https://www.aai.dfn.de
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml",
		WithRegistrationAuthorityFilter("https://www.aai.dfn.de"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// All 4 IdPs in dfn-aai-sample.xml have DFN registration authority
	if len(idps) != 4 {
		t.Errorf("ListIdPs() returned %d IdPs, want 4", len(idps))
	}
}

// TestFileMetadataStore_WithRegistrationAuthorityFilter_NoMatch tests error when no IdPs match
func TestFileMetadataStore_WithRegistrationAuthorityFilter_NoMatch(t *testing.T) {
	// Filter for a federation that doesn't exist in the test data
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml",
		WithRegistrationAuthorityFilter("https://nonexistent.org"))
	err := store.Load()

	// Should fail because no IdPs match
	if err == nil {
		t.Error("Expected error when no IdPs match registration authority filter")
	}
}

// TestFileMetadataStore_WithRegistrationAuthorityFilter_NoRegistrationInfo tests
// that IdPs without registration info are excluded
func TestFileMetadataStore_WithRegistrationAuthorityFilter_NoRegistrationInfo(t *testing.T) {
	// aggregate-metadata.xml has IdPs without registration info
	store := NewFileMetadataStore("testdata/aggregate-metadata.xml",
		WithRegistrationAuthorityFilter("*"))
	err := store.Load()

	// Should fail because IdPs have no registration authority
	if err == nil {
		t.Error("Expected error when IdPs have no registration authority")
	}
}

// TestFileMetadataStore_BothFilters tests combining IdP filter with registration authority filter
func TestFileMetadataStore_BothFilters(t *testing.T) {
	// Filter by both entity ID pattern and registration authority
	store := NewFileMetadataStore("testdata/dfn-aai-sample.xml",
		WithIdPFilter("*berlin*"),
		WithRegistrationAuthorityFilter("https://www.aai.dfn.de"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Only FU Berlin should match both filters
	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}

	if len(idps) > 0 && idps[0].EntityID != "https://identity.fu-berlin.de/idp-fub" {
		t.Errorf("Expected FU Berlin, got %s", idps[0].EntityID)
	}
}
