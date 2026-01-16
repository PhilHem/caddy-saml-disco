//go:build unit

package metadata

import (
	"fmt"
	"github.com/crewjam/saml"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"testing"
	"time"
)

func TestParseIdP_UIInfo_DisplayName(t *testing.T) {
	// DFN-AAI sample has both mdui:DisplayName and OrganizationDisplayName
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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

// TestIdPInfo_StoresAllLanguageVariants verifies that domain.IdPInfo stores all
// language variants of display names, descriptions, and information URLs.
func TestIdPInfo_HasSLOFields(t *testing.T) {
	idp := domain.IdPInfo{
		EntityID:   "https://idp.example.com",
		SLOURL:     "https://idp.example.com/slo",
		SLOBinding: saml.HTTPRedirectBinding,
	}
	if idp.SLOURL == "" {
		t.Error("expected SLOURL field")
	}
	if idp.SLOBinding == "" {
		t.Error("expected SLOBinding field")
	}
	if idp.SLOURL != "https://idp.example.com/slo" {
		t.Errorf("SLOURL = %q, want %q", idp.SLOURL, "https://idp.example.com/slo")
	}
	if idp.SLOBinding != saml.HTTPRedirectBinding {
		t.Errorf("SLOBinding = %q, want %q", idp.SLOBinding, saml.HTTPRedirectBinding)
	}
}

// TestExtractIdPInfo_ParsesSLOEndpoint verifies that SLO endpoints are extracted from metadata.
func TestExtractIdPInfo_ParsesSLOEndpoint(t *testing.T) {
	store := NewFileMetadataStore("../../../../testdata/idp-metadata-with-slo.xml")
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

	if idp.SLOURL != "https://idp.example.com/saml/slo" {
		t.Errorf("SLOURL = %q, want %q", idp.SLOURL, "https://idp.example.com/saml/slo")
	}

	if idp.SLOBinding != saml.HTTPRedirectBinding {
		t.Errorf("SLOBinding = %q, want %q", idp.SLOBinding, saml.HTTPRedirectBinding)
	}
}

// =============================================================================
// Multi-Language Search Tests (Phase 3)
// =============================================================================

// TestMatchesSearch_AllLanguageVariants verifies that search matches against
// ALL language variants of DisplayNames, not just the default DisplayName.
func TestParseIdP_RegistrationInfo_Authority(t *testing.T) {
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/dfn-aai-sample.xml")
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
	store := NewFileMetadataStore("../../../../testdata/idp-metadata.xml")
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
			result := domain.IsMetadataExpired(tc.validUntil, now)
			if result != tc.expected {
				t.Errorf("domain.IsMetadataExpired(%v, %v) = %v, want %v",
					tc.validUntil, now, result, tc.expected)
			}
		})
	}
}

// TestFileMetadataStore_Load_ExpiredMetadata verifies that expired metadata
// is rejected during loading.
func TestExtractEntityIDs_Empty(t *testing.T) {
	result := domain.ExtractEntityIDs(nil)
	if result != nil {
		t.Errorf("domain.ExtractEntityIDs(nil) = %v, want nil", result)
	}

	result = domain.ExtractEntityIDs([]domain.IdPInfo{})
	if result != nil {
		t.Errorf("domain.ExtractEntityIDs([]) = %v, want nil", result)
	}
}

func TestExtractEntityIDs_Single(t *testing.T) {
	idps := []domain.IdPInfo{
		{EntityID: "https://idp.example.org/saml"},
	}
	result := domain.ExtractEntityIDs(idps)
	if len(result) != 1 {
		t.Fatalf("ExtractEntityIDs returned %d items, want 1", len(result))
	}
	if result[0] != "https://idp.example.org/saml" {
		t.Errorf("domain.ExtractEntityIDs()[0] = %q, want %q", result[0], "https://idp.example.org/saml")
	}
}

func TestExtractEntityIDs_Multiple(t *testing.T) {
	idps := []domain.IdPInfo{
		{EntityID: "https://idp1.example.org"},
		{EntityID: "https://idp2.example.org"},
		{EntityID: "https://idp3.example.org"},
	}
	result := domain.ExtractEntityIDs(idps)
	if len(result) != 3 {
		t.Fatalf("ExtractEntityIDs returned %d items, want 3", len(result))
	}
	expected := []string{
		"https://idp1.example.org",
		"https://idp2.example.org",
		"https://idp3.example.org",
	}
	for i, want := range expected {
		if result[i] != want {
			t.Errorf("domain.ExtractEntityIDs()[%d] = %q, want %q", i, result[i], want)
		}
	}
}

func TestExtractEntityIDs_PreservesOrder(t *testing.T) {
	// Create IdPs in reverse alphabetical order to verify no sorting happens
	idps := []domain.IdPInfo{
		{EntityID: "https://z.example.org"},
		{EntityID: "https://a.example.org"},
		{EntityID: "https://m.example.org"},
	}
	result := domain.ExtractEntityIDs(idps)
	if len(result) != 3 {
		t.Fatalf("ExtractEntityIDs returned %d items, want 3", len(result))
	}
	// Order must match input order exactly
	if result[0] != "https://z.example.org" {
		t.Errorf("domain.ExtractEntityIDs()[0] = %q, want https://z.example.org", result[0])
	}
	if result[1] != "https://a.example.org" {
		t.Errorf("domain.ExtractEntityIDs()[1] = %q, want https://a.example.org", result[1])
	}
	if result[2] != "https://m.example.org" {
		t.Errorf("domain.ExtractEntityIDs()[2] = %q, want https://m.example.org", result[2])
	}
}

// Tests for FormatEntityIDList helper function

func TestFormatEntityIDList_Empty(t *testing.T) {
	result := domain.FormatEntityIDList(nil)
	if result != "(none)" {
		t.Errorf("domain.FormatEntityIDList(nil) = %q, want \"(none)\"", result)
	}

	result = domain.FormatEntityIDList([]string{})
	if result != "(none)" {
		t.Errorf("domain.FormatEntityIDList([]) = %q, want \"(none)\"", result)
	}
}

func TestFormatEntityIDList_Single(t *testing.T) {
	result := domain.FormatEntityIDList([]string{"https://idp.example.org"})
	expected := "1 IdPs: [https://idp.example.org]"
	if result != expected {
		t.Errorf("FormatEntityIDList = %q, want %q", result, expected)
	}
}

func TestFormatEntityIDList_Multiple(t *testing.T) {
	ids := []string{
		"https://idp1.example.org",
		"https://idp2.example.org",
		"https://idp3.example.org",
	}
	result := domain.FormatEntityIDList(ids)
	expected := "3 IdPs: [https://idp1.example.org, https://idp2.example.org, https://idp3.example.org]"
	if result != expected {
		t.Errorf("FormatEntityIDList = %q, want %q", result, expected)
	}
}

// Property-based test for ExtractEntityIDs
func TestExtractEntityIDs_Property_LengthPreserved(t *testing.T) {
	// Test with various sizes
	for _, n := range []int{0, 1, 5, 10, 100} {
		idps := make([]domain.IdPInfo, n)
		for i := 0; i < n; i++ {
			idps[i] = domain.IdPInfo{EntityID: fmt.Sprintf("https://idp%d.example.org", i)}
		}
		result := domain.ExtractEntityIDs(idps)

		// Property: length of result equals length of input (or both are nil for empty)
		if n == 0 {
			if result != nil {
				t.Errorf("n=%d: ExtractEntityIDs returned non-nil for empty input", n)
			}
		} else {
			if len(result) != n {
				t.Errorf("n=%d: len(ExtractEntityIDs) = %d, want %d", n, len(result), n)
			}
		}

		// Property: all IDs in result exist in input
		for i, id := range result {
			if id != idps[i].EntityID {
				t.Errorf("n=%d, i=%d: result[%d] = %q, want %q", n, i, i, id, idps[i].EntityID)
			}
		}
	}
}

// =============================================================================
// Metadata Caching Observability Tests (caddy-saml-disco-lat)
// =============================================================================

// TestURLMetadataStore_CacheHitLogging verifies debug log "using cached metadata"
// with ttl_remaining and idp_count when cache is valid.
