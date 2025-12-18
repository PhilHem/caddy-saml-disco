//go:build unit

package caddysamldisco

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
)

// Benchmark metadata parsing with various IdP counts.
// Run with: go test -bench=BenchmarkParseMetadata -benchmem ./...

var metadataTemplate = template.Must(template.New("metadata").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
                    xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"
                    validUntil="2099-12-31T23:59:59Z">
{{range .IdPs}}
    <EntityDescriptor entityID="{{.EntityID}}">
        <Extensions>
            <mdrpi:RegistrationInfo registrationAuthority="{{.RegistrationAuthority}}"
                                    registrationInstant="2020-01-15T10:30:00Z"/>
        </Extensions>
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <Extensions>
                <mdui:UIInfo>
                    <mdui:DisplayName xml:lang="en">{{.DisplayNameEN}}</mdui:DisplayName>
                    <mdui:DisplayName xml:lang="de">{{.DisplayNameDE}}</mdui:DisplayName>
                    <mdui:Description xml:lang="en">{{.DescriptionEN}}</mdui:Description>
                    <mdui:Logo height="64" width="64">{{.LogoURL}}</mdui:Logo>
                    <mdui:InformationURL xml:lang="en">{{.InfoURL}}</mdui:InformationURL>
                </mdui:UIInfo>
            </Extensions>
            <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>{{.Certificate}}</X509Certificate>
                    </X509Data>
                </KeyInfo>
            </KeyDescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="{{.SSOURL}}"/>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="{{.SSOURLPost}}"/>
        </IDPSSODescriptor>
        <Organization>
            <OrganizationName xml:lang="en">{{.OrgName}}</OrganizationName>
            <OrganizationDisplayName xml:lang="en">{{.DisplayNameEN}}</OrganizationDisplayName>
            <OrganizationURL xml:lang="en">{{.OrgURL}}</OrganizationURL>
        </Organization>
    </EntityDescriptor>
{{end}}
</EntitiesDescriptor>
`))

type benchIdPData struct {
	EntityID              string
	DisplayNameEN         string
	DisplayNameDE         string
	DescriptionEN         string
	LogoURL               string
	InfoURL               string
	SSOURL                string
	SSOURLPost            string
	OrgName               string
	OrgURL                string
	Certificate           string
	RegistrationAuthority string
}

type benchTemplateData struct {
	IdPs []benchIdPData
}

// Sample data for variety
var (
	orgTypes = []string{
		"University", "College", "Institute", "Academy", "School",
		"Research Center", "Laboratory", "Foundation", "Hospital", "Library",
	}
	countries = []string{
		"us", "uk", "de", "fr", "nl", "be", "ch", "at", "it", "es",
		"pl", "cz", "se", "no", "dk", "fi", "ie", "pt", "gr", "hu",
	}
	federations = []string{
		"https://incommon.org",
		"https://www.aai.dfn.de",
		"https://www.ukfederation.org.uk",
		"https://federation.renater.fr",
		"https://www.surfconext.nl",
	}
	// Realistic certificate length (~1KB base64)
	fakeCertBase = strings.Repeat("MIICpDCCAYwCCQDU+pQ4P2dP3jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls", 20)
)

// generateMetadataFixture creates a metadata aggregate with n IdPs.
func generateMetadataFixture(n int) []byte {
	data := benchTemplateData{
		IdPs: make([]benchIdPData, n),
	}

	for i := 0; i < n; i++ {
		country := countries[i%len(countries)]
		orgType := orgTypes[i%len(orgTypes)]
		federation := federations[i%len(federations)]

		data.IdPs[i] = benchIdPData{
			EntityID:              fmt.Sprintf("https://idp%04d.%s.example.edu/saml", i, country),
			DisplayNameEN:         fmt.Sprintf("%s of %s %04d", orgType, strings.ToUpper(country), i),
			DisplayNameDE:         fmt.Sprintf("%s von %s %04d", orgType, strings.ToUpper(country), i),
			DescriptionEN:         fmt.Sprintf("Identity Provider for %s of %s, serving students and staff.", orgType, strings.ToUpper(country)),
			LogoURL:               fmt.Sprintf("https://idp%04d.%s.example.edu/logo.png", i, country),
			InfoURL:               fmt.Sprintf("https://idp%04d.%s.example.edu/info", i, country),
			SSOURL:                fmt.Sprintf("https://idp%04d.%s.example.edu/sso/redirect", i, country),
			SSOURLPost:            fmt.Sprintf("https://idp%04d.%s.example.edu/sso/post", i, country),
			OrgName:               fmt.Sprintf("%s of %s", orgType, strings.ToUpper(country)),
			OrgURL:                fmt.Sprintf("https://www.%s%04d.example.edu", country, i),
			Certificate:           base64.StdEncoding.EncodeToString([]byte(fakeCertBase + fmt.Sprintf("%04d", i))),
			RegistrationAuthority: federation,
		}
	}

	var buf bytes.Buffer
	if err := metadataTemplate.Execute(&buf, data); err != nil {
		panic(fmt.Sprintf("failed to generate metadata fixture: %v", err))
	}
	return buf.Bytes()
}

// Pre-generate fixtures for benchmarks to avoid including generation time
var (
	fixture100  = generateMetadataFixture(100)
	fixture500  = generateMetadataFixture(500)
	fixture1000 = generateMetadataFixture(1000)
	fixture5000 = generateMetadataFixture(5000)
)

// BenchmarkParseMetadata_100 benchmarks parsing 100 IdPs.
func BenchmarkParseMetadata_100(b *testing.B) {
	benchmarkParseMetadata(b, fixture100, 100)
}

// BenchmarkParseMetadata_500 benchmarks parsing 500 IdPs.
func BenchmarkParseMetadata_500(b *testing.B) {
	benchmarkParseMetadata(b, fixture500, 500)
}

// BenchmarkParseMetadata_1000 benchmarks parsing 1000 IdPs.
func BenchmarkParseMetadata_1000(b *testing.B) {
	benchmarkParseMetadata(b, fixture1000, 1000)
}

// BenchmarkParseMetadata_5000 benchmarks parsing 5000 IdPs.
func BenchmarkParseMetadata_5000(b *testing.B) {
	benchmarkParseMetadata(b, fixture5000, 5000)
}

func benchmarkParseMetadata(b *testing.B, data []byte, expectedCount int) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))

	var idps []IdPInfo
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idps, _, err = metadata.ParseMetadata(data)
		if err != nil {
			b.Fatalf("ParseMetadata failed: %v", err)
		}
	}
	b.StopTimer()

	if len(idps) != expectedCount {
		b.Errorf("expected %d IdPs, got %d", expectedCount, len(idps))
	}
}

// BenchmarkGetIdP benchmarks looking up an IdP by entity ID.
func BenchmarkGetIdP_100(b *testing.B) {
	benchmarkGetIdP(b, 100)
}

func BenchmarkGetIdP_1000(b *testing.B) {
	benchmarkGetIdP(b, 1000)
}

func BenchmarkGetIdP_5000(b *testing.B) {
	benchmarkGetIdP(b, 5000)
}

func benchmarkGetIdP(b *testing.B, count int) {
	b.Helper()
	store := setupBenchStore(b, count)

	// Look up an entity in the middle of the list
	targetID := fmt.Sprintf("https://idp%04d.%s.example.edu/saml", count/2, countries[(count/2)%len(countries)])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.GetIdP(targetID)
		if err != nil {
			b.Fatalf("GetIdP failed: %v", err)
		}
	}
}

// BenchmarkListIdPs_NoFilter benchmarks listing all IdPs without a filter.
func BenchmarkListIdPs_NoFilter_100(b *testing.B) {
	benchmarkListIdPs(b, 100, "")
}

func BenchmarkListIdPs_NoFilter_1000(b *testing.B) {
	benchmarkListIdPs(b, 1000, "")
}

func BenchmarkListIdPs_NoFilter_5000(b *testing.B) {
	benchmarkListIdPs(b, 5000, "")
}

// BenchmarkListIdPs_WithFilter benchmarks searching IdPs with a filter.
func BenchmarkListIdPs_WithFilter_100(b *testing.B) {
	benchmarkListIdPs(b, 100, "university")
}

func BenchmarkListIdPs_WithFilter_1000(b *testing.B) {
	benchmarkListIdPs(b, 1000, "university")
}

func BenchmarkListIdPs_WithFilter_5000(b *testing.B) {
	benchmarkListIdPs(b, 5000, "university")
}

func benchmarkListIdPs(b *testing.B, count int, filter string) {
	b.Helper()
	store := setupBenchStore(b, count)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.ListIdPs(filter)
		if err != nil {
			b.Fatalf("ListIdPs failed: %v", err)
		}
	}
}

// BenchmarkMatchesSearch benchmarks the search matching function directly.
func BenchmarkMatchesSearch_Match(b *testing.B) {
	idp := &IdPInfo{
		EntityID:    "https://idp0500.us.example.edu/saml",
		DisplayName: "University of US 0500",
		DisplayNames: map[string]string{
			"en": "University of US 0500",
			"de": "Universität von US 0500",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !MatchesSearch(idp, "university") {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkMatchesSearch_NoMatch(b *testing.B) {
	idp := &IdPInfo{
		EntityID:    "https://idp0500.us.example.edu/saml",
		DisplayName: "University of US 0500",
		DisplayNames: map[string]string{
			"en": "University of US 0500",
			"de": "Universität von US 0500",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if MatchesSearch(idp, "nonexistent") {
			b.Fatal("expected no match")
		}
	}
}

// BenchmarkLocalizeIdPInfo benchmarks localization of IdP info.
func BenchmarkLocalizeIdPInfo(b *testing.B) {
	idp := IdPInfo{
		EntityID:    "https://idp0500.us.example.edu/saml",
		DisplayName: "University of US 0500",
		DisplayNames: map[string]string{
			"en":    "University of US 0500",
			"de":    "Universität von US 0500",
			"fr":    "Université des US 0500",
			"es":    "Universidad de US 0500",
			"it":    "Università degli US 0500",
			"nl":    "Universiteit van US 0500",
			"pl":    "Uniwersytet US 0500",
			"pt":    "Universidade dos US 0500",
			"en-GB": "University of US 0500 (UK)",
			"en-US": "University of US 0500 (US)",
		},
		Description: "A test university",
		Descriptions: map[string]string{
			"en": "A test university",
			"de": "Eine Test-Universität",
		},
		InformationURL: "https://example.edu/info",
		InformationURLs: map[string]string{
			"en": "https://example.edu/info",
			"de": "https://example.edu/de/info",
		},
	}
	prefs := []string{"de", "en"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = LocalizeIdPInfo(idp, prefs, "en")
	}
}

// setupBenchStore creates an InMemoryMetadataStore with n IdPs for benchmarking.
func setupBenchStore(b *testing.B, count int) *InMemoryMetadataStore {
	b.Helper()

	var data []byte
	switch {
	case count <= 100:
		data = fixture100
	case count <= 500:
		data = fixture500
	case count <= 1000:
		data = fixture1000
	default:
		data = fixture5000
	}

	idps, _, err := metadata.ParseMetadata(data)
	if err != nil {
		b.Fatalf("failed to parse fixture: %v", err)
	}

	// Trim to exact count if needed
	if len(idps) > count {
		idps = idps[:count]
	}

	return NewInMemoryMetadataStore(idps)
}

// TestMemoryUsage reports steady-state memory usage for IdP storage.
// This measures the memory held by parsed IdPInfo structs, not parsing allocations.
// Run with: go test -v -run TestMemoryUsage
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory usage test in short mode")
	}

	counts := []int{100, 500, 1000, 5000}

	for _, count := range counts {
		t.Run(fmt.Sprintf("%d_IdPs", count), func(t *testing.T) {
			var fixture []byte
			switch count {
			case 100:
				fixture = fixture100
			case 500:
				fixture = fixture500
			case 1000:
				fixture = fixture1000
			case 5000:
				fixture = fixture5000
			}

			// Parse the metadata
			idps, _, err := metadata.ParseMetadata(fixture)
			if err != nil {
				t.Fatalf("ParseMetadata failed: %v", err)
			}

			// Calculate approximate size of IdPInfo slice in memory
			// This is a rough estimate based on struct fields
			idpSize := estimateIdPInfoSize(idps)
			xmlSize := len(fixture)

			t.Logf("XML size: %.2f KB", float64(xmlSize)/1024)
			t.Logf("IdPs parsed: %d", len(idps))
			t.Logf("Estimated IdP storage: %.2f KB", float64(idpSize)/1024)
			t.Logf("Storage per IdP: %.2f KB", float64(idpSize)/float64(len(idps))/1024)
			t.Logf("Memory ratio (storage/XML): %.2f%%", float64(idpSize)/float64(xmlSize)*100)
		})
	}
}

// estimateIdPInfoSize estimates the memory used by a slice of IdPInfo structs.
// This includes the base struct size plus string and map allocations.
func estimateIdPInfoSize(idps []IdPInfo) int {
	total := 0
	for _, idp := range idps {
		// Base struct overhead (pointers, slice headers, etc.) ~200 bytes
		total += 200

		// String fields
		total += len(idp.EntityID)
		total += len(idp.DisplayName)
		total += len(idp.Description)
		total += len(idp.LogoURL)
		total += len(idp.InformationURL)
		total += len(idp.SSOURL)
		total += len(idp.SSOBinding)
		total += len(idp.RegistrationAuthority)

		// Maps (key + value + map overhead per entry ~50 bytes)
		for k, v := range idp.DisplayNames {
			total += len(k) + len(v) + 50
		}
		for k, v := range idp.Descriptions {
			total += len(k) + len(v) + 50
		}
		for k, v := range idp.InformationURLs {
			total += len(k) + len(v) + 50
		}
		for k, v := range idp.RegistrationPolicies {
			total += len(k) + len(v) + 50
		}

		// Certificate strings
		for _, cert := range idp.Certificates {
			total += len(cert)
		}
	}
	return total
}

// BenchmarkRefresh benchmarks the full refresh cycle including file I/O.
func BenchmarkFileMetadataStore_Refresh_1000(b *testing.B) {
	// Write fixture to temp file
	dir := b.TempDir()
	path := dir + "/metadata.xml"
	if err := writeBenchFile(path, fixture1000); err != nil {
		b.Fatalf("failed to write fixture: %v", err)
	}

	store := NewFileMetadataStore(path)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := store.Refresh(context.Background()); err != nil {
			b.Fatalf("Refresh failed: %v", err)
		}
	}
}

func writeBenchFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
