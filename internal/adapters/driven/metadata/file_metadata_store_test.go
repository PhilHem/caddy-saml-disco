//go:build unit

package metadata

import (
	"context"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileMetadataStore_Load(t *testing.T) {
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")

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
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
	if err != domain.ErrIdPNotFound {
		t.Errorf("expected domain.ErrIdPNotFound, got %v", err)
	}
}

func TestFileMetadataStore_ListIdPs_Filter(t *testing.T) {
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
	if err != domain.ErrIdPNotFound {
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
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml")

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
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml")
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
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml")
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
	store := NewFileMetadataStore("../../../../testdata/mixed-metadata.xml")

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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")

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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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

func TestFileMetadataStore_Load_DFNAAISample_EntityAttributes(t *testing.T) {
	// Test parsing of mdattr:EntityAttributes (entity categories and assurance certifications)
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// FU Berlin: Has R&S + SIRTFI
	idp, err := store.GetIdP("https://identity.fu-berlin.de/idp-fub")
	if err != nil {
		t.Fatalf("GetIdP(FU Berlin) failed: %v", err)
	}

	// Check entity categories
	hasRS := false
	for _, cat := range idp.EntityCategories {
		if cat == "http://refeds.org/category/research-and-scholarship" {
			hasRS = true
			break
		}
	}
	if !hasRS {
		t.Errorf("GetIdP(FU Berlin).EntityCategories should contain http://refeds.org/category/research-and-scholarship, got %v", idp.EntityCategories)
	}

	// Check assurance certifications
	hasSIRTFI := false
	for _, cert := range idp.AssuranceCertifications {
		if cert == "https://refeds.org/sirtfi" {
			hasSIRTFI = true
			break
		}
	}
	if !hasSIRTFI {
		t.Errorf("GetIdP(FU Berlin).AssuranceCertifications should contain https://refeds.org/sirtfi, got %v", idp.AssuranceCertifications)
	}

	// TUM: Has R&S + Code of Conduct v2, but no SIRTFI
	idp, err = store.GetIdP("https://tumidp.lrz.de/idp/shibboleth")
	if err != nil {
		t.Fatalf("GetIdP(TUM) failed: %v", err)
	}

	hasRS = false
	hasCoC := false
	for _, cat := range idp.EntityCategories {
		if cat == "http://refeds.org/category/research-and-scholarship" {
			hasRS = true
		}
		if cat == "https://refeds.org/category/code-of-conduct/v2" {
			hasCoC = true
		}
	}
	if !hasRS {
		t.Errorf("GetIdP(TUM).EntityCategories should contain http://refeds.org/category/research-and-scholarship, got %v", idp.EntityCategories)
	}
	if !hasCoC {
		t.Errorf("GetIdP(TUM).EntityCategories should contain https://refeds.org/category/code-of-conduct/v2, got %v", idp.EntityCategories)
	}

	// TUM should not have SIRTFI
	if len(idp.AssuranceCertifications) > 0 {
		t.Errorf("GetIdP(TUM).AssuranceCertifications should be empty, got %v", idp.AssuranceCertifications)
	}

	// RWTH Aachen: Has no EntityAttributes
	idp, err = store.GetIdP("https://login.rz.rwth-aachen.de/shibboleth")
	if err != nil {
		t.Fatalf("GetIdP(RWTH) failed: %v", err)
	}

	if len(idp.EntityCategories) > 0 {
		t.Errorf("GetIdP(RWTH).EntityCategories should be empty, got %v", idp.EntityCategories)
	}
	if len(idp.AssuranceCertifications) > 0 {
		t.Errorf("GetIdP(RWTH).AssuranceCertifications should be empty, got %v", idp.AssuranceCertifications)
	}

	// Max Planck: Has R&S + SIRTFI
	idp, err = store.GetIdP("https://idp.mpg.de/idp/shibboleth")
	if err != nil {
		t.Fatalf("GetIdP(Max Planck) failed: %v", err)
	}

	hasRS = false
	for _, cat := range idp.EntityCategories {
		if cat == "http://refeds.org/category/research-and-scholarship" {
			hasRS = true
			break
		}
	}
	if !hasRS {
		t.Errorf("GetIdP(Max Planck).EntityCategories should contain http://refeds.org/category/research-and-scholarship, got %v", idp.EntityCategories)
	}

	hasSIRTFI = false
	for _, cert := range idp.AssuranceCertifications {
		if cert == "https://refeds.org/sirtfi" {
			hasSIRTFI = true
			break
		}
	}
	if !hasSIRTFI {
		t.Errorf("GetIdP(Max Planck).AssuranceCertifications should contain https://refeds.org/sirtfi, got %v", idp.AssuranceCertifications)
	}
}

func TestFileMetadataStore_Load_NestedEntitiesDescriptor(t *testing.T) {
	// Tests nested EntitiesDescriptor structure (Universities > Labs hierarchy)
	store := NewFileMetadataStore("../../../../testdata/nested-metadata.xml")

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
	if _, err := store.GetIdP("https://sp.library.edu"); err != domain.ErrIdPNotFound {
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
	if _, err := store.GetIdP("https://idp2.example.com"); err != domain.ErrIdPNotFound {
		t.Error("idp2 should not be found after refresh")
	}
	if _, err := store.GetIdP("https://idp3.example.com"); err != nil {
		t.Error("idp3 should be found after refresh")
	}
}

// URLMetadataStore tests

func TestFileMetadataStore_WithIdPFilter(t *testing.T) {
	// Load aggregate metadata with filter
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml", WithIdPFilter("*idp1*"))
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
	if err != domain.ErrIdPNotFound {
		t.Error("Filtered IdP should not be accessible via GetIdP")
	}
}

func TestFileMetadataStore_WithIdPFilter_NoMatch(t *testing.T) {
	// Filter that matches nothing
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml", WithIdPFilter("*nonexistent*"))
	err := store.Load()

	// Should fail because no IdPs match
	if err == nil {
		t.Error("Expected error when no IdPs match filter")
	}
}

func TestFileMetadataStore_WithIdPFilter_Empty(t *testing.T) {
	// Empty filter should load all IdPs (same as no filter)
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml", WithIdPFilter(""))
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml", WithIdPFilter("*berlin*"))
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
	if err != domain.ErrIdPNotFound {
		t.Error("Blocked IdP should not be accessible after refresh")
	}
}

func TestInMemoryMetadataStore_Health(t *testing.T) {
	store := NewInMemoryMetadataStore([]domain.IdPInfo{
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
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml")
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
func TestFileMetadataStore_Health_ReturnsValidUntil(t *testing.T) {
	// Use dfn-aai-sample.xml which has validUntil="2030-12-31T23:59:59Z"
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	health := store.Health()

	if health.MetadataValidUntil == nil {
		t.Fatal("Health.MetadataValidUntil should be set for metadata with validUntil")
	}

	expected := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
	if !health.MetadataValidUntil.Equal(expected) {
		t.Errorf("MetadataValidUntil = %v, want %v", *health.MetadataValidUntil, expected)
	}
}

func TestFileMetadataStore_Health_NoValidUntil(t *testing.T) {
	// Use idp-metadata.xml which has no validUntil attribute
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
		[]domain.IdPInfo{{EntityID: "https://idp.example.com"}},
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
	store := NewInMemoryMetadataStore([]domain.IdPInfo{{EntityID: "https://idp.example.com"}})

	health := store.Health()

	if health.MetadataValidUntil != nil {
		t.Errorf("MetadataValidUntil should be nil, got %v", *health.MetadataValidUntil)
	}
}

func TestFileMetadataStore_RecordsMetricsOnSuccess(t *testing.T) {
	mock := &MockMetricsRecorder{}
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml", WithMetricsRecorder(mock))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	calls := mock.GetMetadataRefreshes()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.Source != "file" {
		t.Errorf("source = %q, want %q", call.Source, "file")
	}
	if !call.Success {
		t.Error("success = false, want true")
	}
	if call.IdpCount != 1 {
		t.Errorf("idpCount = %d, want 1", call.IdpCount)
	}
}

func TestFileMetadataStore_RecordsMetricsOnFailure(t *testing.T) {
	mock := &MockMetricsRecorder{}
	store := NewFileMetadataStore("/nonexistent/path/metadata.xml", WithMetricsRecorder(mock))

	err := store.Load()
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	calls := mock.GetMetadataRefreshes()
	if len(calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(calls))
	}

	call := calls[0]
	if call.Source != "file" {
		t.Errorf("source = %q, want %q", call.Source, "file")
	}
	if call.Success {
		t.Error("success = true, want false")
	}
	if call.IdpCount != 0 {
		t.Errorf("idpCount = %d, want 0", call.IdpCount)
	}
}

func TestFileMetadataStore_WithRegistrationAuthorityFilter(t *testing.T) {
	// dfn-aai-sample.xml contains IdPs registered by https://www.aai.dfn.de
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
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
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml",
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
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

// TestFilterIdPsByEntityCategory tests the pure domain filter function
func TestFileMetadataStore_WithEntityCategoryFilter(t *testing.T) {
	// dfn-aai-sample.xml contains:
	// - FU Berlin: R&S + SIRTFI
	// - TUM: R&S + Code of Conduct v2
	// - RWTH Aachen: No entity categories
	// - Max Planck: R&S + SIRTFI
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
		WithEntityCategoryFilter("http://refeds.org/category/research-and-scholarship"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Should return FU Berlin, TUM, and Max Planck (3 IdPs with R&S)
	if len(idps) != 3 {
		t.Errorf("ListIdPs() returned %d IdPs, want 3", len(idps))
	}

	// Verify all returned IdPs have R&S category
	for _, idp := range idps {
		hasRS := false
		for _, cat := range idp.EntityCategories {
			if cat == "http://refeds.org/category/research-and-scholarship" {
				hasRS = true
				break
			}
		}
		if !hasRS {
			t.Errorf("IdP %q does not have R&S category", idp.EntityID)
		}
	}
}

// TestFileMetadataStore_WithEntityCategoryFilter_NoMatch tests error when no IdPs match
func TestFileMetadataStore_WithEntityCategoryFilter_NoMatch(t *testing.T) {
	// Filter for a category that doesn't exist in the test data
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
		WithEntityCategoryFilter("https://nonexistent.org/category"))
	err := store.Load()

	// Should fail because no IdPs match
	if err == nil {
		t.Error("Expected error when no IdPs match entity category filter")
	}
}

// TestFileMetadataStore_WithAssuranceCertificationFilter tests filtering via FileMetadataStore
func TestFileMetadataStore_WithAssuranceCertificationFilter(t *testing.T) {
	// dfn-aai-sample.xml contains:
	// - FU Berlin: R&S + SIRTFI
	// - TUM: R&S + Code of Conduct v2 (no SIRTFI)
	// - RWTH Aachen: No entity categories
	// - Max Planck: R&S + SIRTFI
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
		WithAssuranceCertificationFilter("https://refeds.org/sirtfi"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Should return FU Berlin and Max Planck (2 IdPs with SIRTFI)
	if len(idps) != 2 {
		t.Errorf("ListIdPs() returned %d IdPs, want 2", len(idps))
	}

	// Verify all returned IdPs have SIRTFI certification
	for _, idp := range idps {
		hasSIRTFI := false
		for _, cert := range idp.AssuranceCertifications {
			if cert == "https://refeds.org/sirtfi" {
				hasSIRTFI = true
				break
			}
		}
		if !hasSIRTFI {
			t.Errorf("IdP %q does not have SIRTFI certification", idp.EntityID)
		}
	}
}

// TestFileMetadataStore_WithAssuranceCertificationFilter_NoMatch tests error when no IdPs match
func TestFileMetadataStore_WithAssuranceCertificationFilter_NoMatch(t *testing.T) {
	// Filter for a certification that doesn't exist in the test data
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
		WithAssuranceCertificationFilter("https://nonexistent.org/cert"))
	err := store.Load()

	// Should fail because no IdPs match
	if err == nil {
		t.Error("Expected error when no IdPs match assurance certification filter")
	}
}

// TestFileMetadataStore_AllFilters tests combining all filters
func TestFileMetadataStore_AllFilters(t *testing.T) {
	// Filter by entity ID pattern, registration authority, entity category, and assurance certification
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml",
		WithIdPFilter("*berlin*"),
		WithRegistrationAuthorityFilter("https://www.aai.dfn.de"),
		WithEntityCategoryFilter("http://refeds.org/category/research-and-scholarship"),
		WithAssuranceCertificationFilter("https://refeds.org/sirtfi"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}

	// Only FU Berlin should match all filters
	if len(idps) != 1 {
		t.Errorf("ListIdPs() returned %d IdPs, want 1", len(idps))
	}

	if len(idps) > 0 && idps[0].EntityID != "https://identity.fu-berlin.de/idp-fub" {
		t.Errorf("Expected FU Berlin, got %s", idps[0].EntityID)
	}
}

// =============================================================================
// Property Tests - Filter Error Messages
// =============================================================================

// TestFileMetadataStore_Property_MultipleFilterFailures_DeterministicError
// tests that when multiple filters would reduce the IdP set to zero, the error
// message is deterministic and includes all failing filters.
// This addresses METADATA-014 and METADATA-015.
func TestFileMetadataStore_Property_MultipleFilterFailures_DeterministicError(t *testing.T) {
	// Use aggregate-metadata.xml which has 3 IdPs
	// Set up multiple filters that would all independently fail (reduce IdP set to zero)
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml",
		WithIdPFilter("*nonexistent*"),                                   // Would fail: no IdPs match
		WithRegistrationAuthorityFilter("https://nonexistent.org"),       // Would fail: no IdPs have this registration authority
		WithEntityCategoryFilter("https://nonexistent.org/category"),     // Would fail: no IdPs have this category
		WithAssuranceCertificationFilter("https://nonexistent.org/cert"), // Would fail: no IdPs have this certification
	)

	err := store.Load()

	// Should fail because multiple filters would reduce IdP set to zero
	if err == nil {
		t.Fatal("Expected error when multiple filters would fail")
	}

	// Property 1: Error message should include all failing filters
	errMsg := err.Error()

	// Check that all failing filters are mentioned in the error
	expectedFilters := []string{
		"filter pattern",
		"registration authority filter",
		"entity category filter",
		"assurance certification filter",
	}

	for _, expected := range expectedFilters {
		if !strings.Contains(errMsg, expected) {
			t.Errorf("Error message should mention %q, got: %q", expected, errMsg)
		}
	}

	// Property 2: Error message should be deterministic (same message every time)
	// Run multiple times to verify determinism
	for i := 0; i < 5; i++ {
		store2 := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml",
			WithIdPFilter("*nonexistent*"),
			WithRegistrationAuthorityFilter("https://nonexistent.org"),
			WithEntityCategoryFilter("https://nonexistent.org/category"),
			WithAssuranceCertificationFilter("https://nonexistent.org/cert"),
		)
		err2 := store2.Load()
		if err2 == nil {
			t.Fatal("Expected error on iteration", i)
		}
		if err2.Error() != errMsg {
			t.Errorf("Error message not deterministic: got %q, want %q", err2.Error(), errMsg)
		}
	}
}

// TestFileMetadataStore_Property_PartialFilterFailures tests that when some filters
// would fail but others would succeed, only the failing filters are reported.
func TestFileMetadataStore_Property_PartialFilterFailures(t *testing.T) {
	// Use aggregate-metadata.xml which has 3 IdPs: idp1, idp2, idp3
	// Set up filters where some would fail and some would succeed
	store := NewFileMetadataStore("../../../../testdata/aggregate-metadata.xml",
		WithIdPFilter("*idp1*"), // Would succeed: matches idp1
		WithRegistrationAuthorityFilter("https://nonexistent.org"),   // Would fail: no IdPs have this registration authority
		WithEntityCategoryFilter("https://nonexistent.org/category"), // Would fail: no IdPs have this category
	)

	err := store.Load()

	// Should fail because registration authority and entity category filters would fail
	if err == nil {
		t.Fatal("Expected error when some filters would fail")
	}

	errMsg := err.Error()

	// Should mention the failing filters
	if !strings.Contains(errMsg, "registration authority filter") {
		t.Errorf("Error message should mention registration authority filter, got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "entity category filter") {
		t.Errorf("Error message should mention entity category filter, got: %q", errMsg)
	}

	// Should NOT mention the IdP filter (which would succeed)
	if strings.Contains(errMsg, "filter pattern") {
		t.Errorf("Error message should not mention IdP filter pattern (it would succeed), got: %q", errMsg)
	}
}

// TestURLMetadataStore_Property_MultipleFilterFailures_DeterministicError
// tests that when multiple filters would reduce the IdP set to zero, the error
// message is deterministic and includes all failing filters.
// This addresses METADATA-014 and METADATA-015.
func TestFileMetadataStore_StartupLogging(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml", WithLogger(logger))

	if err := store.Load(); err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Assert: metadata loaded log
	loadedLogs := logs.FilterMessage("metadata loaded")
	if loadedLogs.Len() == 0 {
		t.Error("expected 'metadata loaded' info log")
	}

	if loadedLogs.Len() > 0 {
		entry := loadedLogs.All()[0]
		fields := entry.ContextMap()
		if _, ok := fields["source"]; !ok {
			t.Error("expected source field in loaded log")
		}
		if _, ok := fields["idp_count"]; !ok {
			t.Error("expected idp_count field in loaded log")
		}
		if _, ok := fields["duration"]; !ok {
			t.Error("expected duration field in loaded log")
		}
	}
}
