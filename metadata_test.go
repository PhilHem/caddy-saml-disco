//go:build unit

package caddysamldisco

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

	// Verify specific German universities/institutions are present
	// Note: DisplayName comes from Organization/OrganizationDisplayName (not yet mdui:UIInfo)
	tests := []struct {
		entityID    string
		displayName string
	}{
		{"https://identity.fu-berlin.de/idp-fub", "Freie Universität Berlin"},
		{"https://tumidp.lrz.de/idp/shibboleth", "Technical University of Munich (TUM)"},
		{"https://login.rz.rwth-aachen.de/shibboleth", "Rheinisch-Westfälische Technische Hochschule Aachen"},
		{"https://shib-idp.awi.de/idp/shibboleth", "Alfred Wegener Institute (AWI)"},
		{"https://idp.mpg.de/idp/shibboleth", "Max Planck Society"},
		{"https://mylogin.uni-freiburg.de/shibboleth", "Albert-Ludwigs-Universität Freiburg"},
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

	// Filter for "University" should match TUM only (1 of 6)
	// RWTH uses German "Hochschule" in OrganizationDisplayName
	idps, err := store.ListIdPs("University")
	if err != nil {
		t.Fatalf("ListIdPs(University) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(University) returned %d IdPs, want 1 (TUM)", len(idps))
	}

	// Filter for "Berlin" should match FU Berlin (1 of 6)
	idps, err = store.ListIdPs("Berlin")
	if err != nil {
		t.Fatalf("ListIdPs(Berlin) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(Berlin) returned %d IdPs, want 1", len(idps))
	}

	// Filter for German "Universität" should match 2 institutions:
	// FU Berlin, Uni Freiburg (TUM uses "Technische Universität")
	idps, err = store.ListIdPs("Universität")
	if err != nil {
		t.Fatalf("ListIdPs(Universität) failed: %v", err)
	}

	if len(idps) != 2 {
		t.Errorf("ListIdPs(Universität) returned %d IdPs, want 2", len(idps))
	}

	// Filter for "Hochschule" should match RWTH Aachen only (1 of 6)
	// (Rheinisch-Westfälische Technische Hochschule Aachen)
	idps, err = store.ListIdPs("Hochschule")
	if err != nil {
		t.Fatalf("ListIdPs(Hochschule) failed: %v", err)
	}

	if len(idps) != 1 {
		t.Errorf("ListIdPs(Hochschule) returned %d IdPs, want 1 (RWTH)", len(idps))
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
		"https://idp.federation.example.org",   // top-level
		"https://idp.university-north.edu",     // nested: Universities
		"https://idp.university-south.edu",     // nested: Universities
		"https://idp.research-center.org",      // nested: Research Institutes
		"https://idp.physics-lab.org",          // deeply nested: Research > Labs
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

	// Use very short TTL
	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

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

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First fetch - should get full response with ETag
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

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

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First fetch
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

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

	store := NewURLMetadataStore(server.URL, 10*time.Millisecond)

	// First fetch - single IdP
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, _ := store.ListIdPs("")
	if len(idps) != 1 {
		t.Fatalf("expected 1 IdP after first load, got %d", len(idps))
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

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
