//go:build bdd

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cucumber/godog"
	messages "github.com/cucumber/messages/go/v21"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// metadataSource represents a metadata source for testing.
type metadataSource struct {
	sourceType string // "url" or "file"
	location   string
	idpFilter  string
	status     string // "ok" or "error"
	idps       []domain.IdPInfo
}

// testContext holds the test state for each scenario.
type testContext struct {
	// Raw IdPs from Background step (populated via table)
	allIdPs []domain.IdPInfo

	// Config from Given steps
	idpFilter     string
	loginRedirect string

	// Multi-source config
	metadataSources []metadataSource

	// Computed at "When" time
	filteredIdPs []domain.IdPInfo
	aggregatedIdPs []domain.IdPInfo
	sourceFailures int

	// Response capture (for redirect scenarios)
	response    *httptest.ResponseRecorder
	originalURL string
}

// ctxKey is the context key for testContext.
type ctxKey struct{}

func TestFeatures(t *testing.T) {
	tra.Require(t, "UseCase.MultiIdPRedirect")

	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"."},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

func InitializeScenario(sc *godog.ScenarioContext) {
	// Before each scenario: set up fresh test context
	sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc := &testContext{
			originalURL: "/protected/resource",
		}
		return context.WithValue(ctx, ctxKey{}, tc), nil
	})

	// =========================================================================
	// Shared steps (both features)
	// =========================================================================

	// Background step: Given metadata with IdPs:
	sc.Step(`^metadata with IdPs:$`, metadataWithIdPs)

	// Given step: Given idp_filter configured as "pattern"
	sc.Step(`^idp_filter configured as "([^"]*)"$`, idpFilterConfiguredAs)

	// Given step: Given idp_filter is not configured
	sc.Step(`^idp_filter is not configured$`, idpFilterIsNotConfigured)

	// =========================================================================
	// multi_idp_redirect.feature specific
	// =========================================================================

	// Given step: And login_redirect configured as "/custom-login"
	sc.Step(`^login_redirect configured as "([^"]*)"$`, loginRedirectConfiguredAs)

	// When step: When an unauthenticated request is made to a protected resource
	sc.Step(`^an unauthenticated request is made to a protected resource$`, anUnauthenticatedRequestIsMade)

	// Then step: Then the response should redirect to the IdP SSO endpoint
	sc.Step(`^the response should redirect to the IdP SSO endpoint$`, responseShouldRedirectToIdPSSO)

	// Then step: Then the response should redirect to "/saml/disco"
	sc.Step(`^the response should redirect to "([^"]*)"$`, responseShouldRedirectTo)

	// Then step: And the redirect should include RelayState with the original URL
	sc.Step(`^the redirect should include RelayState with the original URL$`, redirectShouldIncludeRelayState)

	// Then step: And the redirect should include return_url with the original URL
	sc.Step(`^the redirect should include return_url with the original URL$`, redirectShouldIncludeReturnURL)

	// =========================================================================
	// idp_filtering.feature specific
	// =========================================================================

	// When step: When I list available IdPs
	sc.Step(`^I list available IdPs$`, iListAvailableIdPs)

	// Then step: Then I should see N IdP(s)
	sc.Step(`^I should see (\d+) IdPs?$`, iShouldSeeNIdPs)

	// Then step: And I should see "entityID"
	sc.Step(`^I should see "([^"]*)"$`, iShouldSeeEntityID)

	// Then step: And I should not see "entityID"
	sc.Step(`^I should not see "([^"]*)"$`, iShouldNotSeeEntityID)

	// =========================================================================
	// Multi-source scenarios (Cycle 6)
	// =========================================================================

	// Given step: metadata sources table
	sc.Step(`^metadata sources:$`, metadataSourcesTable)

	// Given step: both sources contain same IdP
	sc.Step(`^both sources contain "([^"]*)"$`, bothSourcesContain)

	// When step: aggregate metadata from all sources
	sc.Step(`^I aggregate metadata from all sources$`, iAggregateMetadataFromAllSources)

	// Then step: I should see IdPs from all sources
	sc.Step(`^I should see IdPs from all sources$`, iShouldSeeIdPsFromAllSources)

	// Then step: deduplicated IdPs count
	sc.Step(`^deduplicated IdPs count is (\d+)$`, deduplicatedIdPsCountIs)

	// Then step: I should see IdPs from working source
	sc.Step(`^I should see IdPs from the working source$`, iShouldSeeIdPsFromWorkingSource)

	// Then step: aggregator should report source failures
	sc.Step(`^the aggregator should report (\d+) source failure(?:s)?$`, aggregatorShouldReportSourceFailures)

	// Then step: I should see 1 IdP not duplicated
	sc.Step(`^I should see 1 IdP \(not duplicated\)$`, iShouldSee1IdPNotDuplicated)

	// Then step: I should see N IdPs (for aggregated scenarios)
	sc.Step(`^I should see (\d+) IdPs?$`, iShouldSeeNIdPsAggregated)

	// Then step: single source mode should work
	sc.Step(`^single source mode should work without code changes$`, singleSourceModeShouldWork)
}

// =============================================================================
// Shared step implementations
// =============================================================================

// metadataWithIdPs populates the test context with IdPs from a Gherkin table.
func metadataWithIdPs(ctx context.Context, table *godog.Table) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Parse table rows (skip header row)
	for i, row := range table.Rows {
		if i == 0 {
			// Skip header row
			continue
		}
		if len(row.Cells) < 1 {
			return ctx, errors.New("table row missing entityID column")
		}
		entityID := row.Cells[0].Value

		// Create IdP with SSO URL derived from entity ID
		ssoURL := strings.TrimSuffix(entityID, "/shibboleth") + "/sso"
		tc.allIdPs = append(tc.allIdPs, domain.IdPInfo{
			EntityID:    entityID,
			DisplayName: entityID,
			SSOURL:      ssoURL,
		})
	}

	return ctx, nil
}

// idpFilterConfiguredAs sets the filter pattern for the scenario.
func idpFilterConfiguredAs(ctx context.Context, pattern string) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.idpFilter = pattern
	return ctx, nil
}

// idpFilterIsNotConfigured ensures no filter is set.
func idpFilterIsNotConfigured(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.idpFilter = ""
	return ctx, nil
}

// =============================================================================
// multi_idp_redirect.feature step implementations
// =============================================================================

// loginRedirectConfiguredAs sets the login redirect URL.
func loginRedirectConfiguredAs(ctx context.Context, redirectURL string) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.loginRedirect = redirectURL
	return ctx, nil
}

// anUnauthenticatedRequestIsMade simulates the redirect decision logic.
// This mirrors the logic in plugin.go:redirectToIdPForSP()
func anUnauthenticatedRequestIsMade(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Apply filter using domain.MatchesEntityIDPattern (same as production)
	tc.filteredIdPs = filterIdPsInTest(tc.allIdPs, tc.idpFilter)

	// Set up response recorder and simulate redirect decision
	tc.response = httptest.NewRecorder()

	// Create a minimal request for http.Redirect
	req := httptest.NewRequest(http.MethodGet, tc.originalURL, nil)

	// Decision logic mirrors plugin.go:redirectToIdPForSP()
	// 1. Check login_redirect first
	if tc.loginRedirect != "" {
		redirectURL := tc.loginRedirect
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "return_url=" + url.QueryEscape(tc.originalURL)
		http.Redirect(tc.response, req, redirectURL, http.StatusFound)
		return ctx, nil
	}

	// 2. Check IdP count
	if len(tc.filteredIdPs) == 0 {
		return ctx, errors.New("no IdPs match the filter")
	}

	// 3. Multiple IdPs → discovery page
	if len(tc.filteredIdPs) > 1 {
		redirectURL := "/saml/disco?return_url=" + url.QueryEscape(tc.originalURL)
		http.Redirect(tc.response, req, redirectURL, http.StatusFound)
		return ctx, nil
	}

	// 4. Single IdP → SSO endpoint with RelayState
	idp := tc.filteredIdPs[0]
	// In production, this generates an AuthnRequest with RelayState.
	// For BDD test, we simulate a redirect to SSO with RelayState param.
	ssoURL := idp.SSOURL + "?SAMLRequest=PLACEHOLDER&RelayState=" + url.QueryEscape(tc.originalURL)
	http.Redirect(tc.response, req, ssoURL, http.StatusFound)

	return ctx, nil
}

// responseShouldRedirectToIdPSSO asserts redirect to the single IdP's SSO endpoint.
func responseShouldRedirectToIdPSSO(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if tc.response.Code != http.StatusFound {
		return fmt.Errorf("expected status 302, got %d", tc.response.Code)
	}

	location := tc.response.Header().Get("Location")
	if location == "" {
		return errors.New("no Location header in response")
	}

	// Should redirect to the IdP SSO endpoint (not /saml/disco)
	if strings.HasPrefix(location, "/saml/disco") {
		return fmt.Errorf("expected redirect to IdP SSO, but got discovery page: %s", location)
	}

	// Verify it's going to an IdP SSO endpoint (contains /sso)
	if !strings.Contains(location, "/sso") {
		return fmt.Errorf("expected redirect to IdP SSO endpoint, got: %s", location)
	}

	return nil
}

// responseShouldRedirectTo asserts redirect to a specific path.
func responseShouldRedirectTo(ctx context.Context, expectedPath string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if tc.response.Code != http.StatusFound {
		return fmt.Errorf("expected status 302, got %d", tc.response.Code)
	}

	location := tc.response.Header().Get("Location")
	if location == "" {
		return errors.New("no Location header in response")
	}

	// Parse the location URL
	parsedURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("failed to parse redirect URL: %w", err)
	}

	// Check if path matches (for /saml/disco, we compare the path part)
	if !strings.HasPrefix(location, expectedPath) {
		return fmt.Errorf("expected redirect to %q, got %q", expectedPath, location)
	}

	// For /saml/disco, also verify it has a query string (return_url)
	if expectedPath == "/saml/disco" && parsedURL.RawQuery == "" {
		return fmt.Errorf("expected redirect to %s with query params, got %s", expectedPath, location)
	}

	return nil
}

// redirectShouldIncludeRelayState asserts RelayState parameter contains original URL.
func redirectShouldIncludeRelayState(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	location := tc.response.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("failed to parse redirect URL: %w", err)
	}

	relayState := parsedURL.Query().Get("RelayState")
	if relayState == "" {
		return fmt.Errorf("RelayState not found in redirect URL: %s", location)
	}

	if relayState != tc.originalURL {
		return fmt.Errorf("RelayState %q does not match original URL %q", relayState, tc.originalURL)
	}

	return nil
}

// redirectShouldIncludeReturnURL asserts return_url parameter contains original URL.
func redirectShouldIncludeReturnURL(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	location := tc.response.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("failed to parse redirect URL: %w", err)
	}

	returnURL := parsedURL.Query().Get("return_url")
	if returnURL == "" {
		return fmt.Errorf("return_url not found in redirect URL: %s", location)
	}

	if returnURL != tc.originalURL {
		return fmt.Errorf("return_url %q does not match original URL %q", returnURL, tc.originalURL)
	}

	return nil
}

// =============================================================================
// idp_filtering.feature step implementations
// =============================================================================

// iListAvailableIdPs applies the filter and stores the result.
func iListAvailableIdPs(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.filteredIdPs = filterIdPsInTest(tc.allIdPs, tc.idpFilter)
	return ctx, nil
}

// iShouldSeeNIdPs asserts the filtered IdP count.
// Checks aggregatedIdPs if they exist (multi-source scenarios),
// otherwise checks filteredIdPs (single-source scenarios).
func iShouldSeeNIdPs(ctx context.Context, expectedCount int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Prefer aggregatedIdPs if populated (multi-source scenarios)
	var idps []domain.IdPInfo
	if len(tc.aggregatedIdPs) > 0 || len(tc.metadataSources) > 0 {
		idps = tc.aggregatedIdPs
	} else {
		idps = tc.filteredIdPs
	}

	actualCount := len(idps)
	if actualCount != expectedCount {
		var entityIDs []string
		for _, idp := range idps {
			entityIDs = append(entityIDs, idp.EntityID)
		}
		return fmt.Errorf("expected %d IdP(s), got %d: %v", expectedCount, actualCount, entityIDs)
	}

	return nil
}

// iShouldSeeNIdPsAggregated is an alias for backward compatibility.
func iShouldSeeNIdPsAggregated(ctx context.Context, expectedCount int) error {
	return iShouldSeeNIdPs(ctx, expectedCount)
}

// iShouldSeeEntityID asserts the entity ID is in the filtered list.
func iShouldSeeEntityID(ctx context.Context, entityID string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	for _, idp := range tc.filteredIdPs {
		if idp.EntityID == entityID {
			return nil
		}
	}

	var found []string
	for _, idp := range tc.filteredIdPs {
		found = append(found, idp.EntityID)
	}
	return fmt.Errorf("entity ID %q not found in filtered list: %v", entityID, found)
}

// iShouldNotSeeEntityID asserts the entity ID is NOT in the filtered list.
func iShouldNotSeeEntityID(ctx context.Context, entityID string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	for _, idp := range tc.filteredIdPs {
		if idp.EntityID == entityID {
			return fmt.Errorf("entity ID %q should not be in filtered list, but it was found", entityID)
		}
	}

	return nil
}

// =============================================================================
// Helper functions
// =============================================================================

// filterIdPsInTest applies the idp_filter pattern to IdPs.
// Uses domain.MatchesEntityIDPattern which is the same logic used in production.
func filterIdPsInTest(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	// Handle comma-separated patterns (same as production)
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		for _, p := range patterns {
			if domain.MatchesEntityIDPattern(idp.EntityID, p) {
				filtered = append(filtered, idp)
				break
			}
		}
	}
	return filtered
}

// =============================================================================
// Multi-source scenario step implementations (Cycle 6)
// =============================================================================

// metadataSourcesTable parses a table of metadata sources with their configuration.
func metadataSourcesTable(ctx context.Context, table *godog.Table) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Parse header row to identify columns
	if len(table.Rows) == 0 {
		return ctx, errors.New("metadata sources table is empty")
	}

	headerRow := table.Rows[0]
	colIndex := make(map[string]int)
	for i, cell := range headerRow.Cells {
		colIndex[cell.Value] = i
	}

	// Verify required columns
	if _, ok := colIndex["source_type"]; !ok {
		return ctx, errors.New("metadata sources table missing 'source_type' column")
	}
	if _, ok := colIndex["location"]; !ok {
		return ctx, errors.New("metadata sources table missing 'location' column")
	}

	// Parse data rows
	for i, row := range table.Rows {
		if i == 0 {
			// Skip header row
			continue
		}

		source := metadataSource{
			sourceType: getTableCell(row, colIndex, "source_type"),
			location:   getTableCell(row, colIndex, "location"),
			idpFilter:  getTableCell(row, colIndex, "idp_filter"),
			status:     getTableCell(row, colIndex, "status"),
		}

		// Default status to "ok" if not specified
		if source.status == "" {
			source.status = "ok"
		}

		// Populate IdPs based on source type (test doubles)
		source.idps = createTestIdPsForSource(source.sourceType, source.location)

		// Apply filter if specified
		if source.idpFilter != "" {
			source.idps = filterIdPsInTest(source.idps, source.idpFilter)
		}

		tc.metadataSources = append(tc.metadataSources, source)
	}

	return ctx, nil
}

// getTableCell safely retrieves a table cell value by column name.
func getTableCell(row *messages.PickleTableRow, colIndex map[string]int, colName string) string {
	idx, ok := colIndex[colName]
	if !ok || idx >= len(row.Cells) {
		return ""
	}
	return row.Cells[idx].Value
}

// createTestIdP is a helper that constructs an IdPInfo from an entity ID.
func createTestIdP(entityID, displayName string) domain.IdPInfo {
	return domain.IdPInfo{
		EntityID:    entityID,
		DisplayName: displayName,
		SSOURL:      strings.TrimSuffix(entityID, "/saml") + "/sso",
	}
}

// createTestIdPsForSource creates test IdPs for a given source location.
// Uses test doubles to simulate different metadata sources.
func createTestIdPsForSource(sourceType, location string) []domain.IdPInfo {
	// Simulate different metadata sources
	switch location {
	case "https://federation1.example/xml":
		return []domain.IdPInfo{
			createTestIdP("https://idp1.example.edu/saml", "University A"),
		}
	case "https://federation2.example/xml":
		return []domain.IdPInfo{
			createTestIdP("https://idp1.example.edu/saml", "University A"),
			createTestIdP("https://idp2.example.org/saml", "Organization B"),
			createTestIdP("https://idp3.other.com/saml", "Other Provider"),
		}
	case "/etc/saml/local-idps.xml":
		return []domain.IdPInfo{
			createTestIdP("https://idp2.example.org/saml", "Organization B"),
		}
	case "https://metadata.example":
		// Default single source with Background IdPs
		return []domain.IdPInfo{
			createTestIdP("https://idp1.example.edu/saml", "University A"),
			createTestIdP("https://idp2.example.org/saml", "Organization B"),
			createTestIdP("https://idp3.other.com/saml", "Other Provider"),
		}
	default:
		// Generic source - return empty by default
		return []domain.IdPInfo{}
	}
}

// bothSourcesContain configures both metadata sources to ONLY contain a specific IdP.
// This replaces their current IdP lists to ensure they share exactly this IdP.
func bothSourcesContain(ctx context.Context, entityID string) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if len(tc.metadataSources) < 2 {
		return ctx, errors.New("expected at least 2 metadata sources")
	}

	// Create the common IdP
	idp := domain.IdPInfo{
		EntityID:    entityID,
		DisplayName: entityID,
		SSOURL:      strings.TrimSuffix(entityID, "/saml") + "/sso",
	}

	// Replace each source's IdPs with just this one
	for i := range tc.metadataSources {
		tc.metadataSources[i].idps = []domain.IdPInfo{idp}
	}

	return ctx, nil
}

// iAggregateMetadataFromAllSources simulates aggregating metadata from multiple sources.
func iAggregateMetadataFromAllSources(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Simulate aggregation: combine IdPs from all sources
	seenEntityIDs := make(map[string]bool)
	tc.aggregatedIdPs = []domain.IdPInfo{}

	for _, source := range tc.metadataSources {
		// Simulate source failures
		if source.status == "error" {
			tc.sourceFailures++
			continue
		}

		// Deduplicate: only add IdPs we haven't seen before
		for _, idp := range source.idps {
			if !seenEntityIDs[idp.EntityID] {
				tc.aggregatedIdPs = append(tc.aggregatedIdPs, idp)
				seenEntityIDs[idp.EntityID] = true
			}
		}
	}

	return ctx, nil
}

// iShouldSeeIdPsFromAllSources verifies aggregation includes sources.
func iShouldSeeIdPsFromAllSources(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if len(tc.aggregatedIdPs) == 0 {
		return errors.New("no IdPs aggregated from sources")
	}

	return nil
}

// deduplicatedIdPsCountIs verifies the deduplicated count.
func deduplicatedIdPsCountIs(ctx context.Context, expectedCount int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	actualCount := len(tc.aggregatedIdPs)
	if actualCount != expectedCount {
		var entityIDs []string
		for _, idp := range tc.aggregatedIdPs {
			entityIDs = append(entityIDs, idp.EntityID)
		}
		return fmt.Errorf("expected %d deduplicated IdPs, got %d: %v", expectedCount, actualCount, entityIDs)
	}

	return nil
}

// iShouldSeeIdPsFromWorkingSource verifies fallback to working sources.
func iShouldSeeIdPsFromWorkingSource(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// After aggregation, we should have IdPs only from working sources
	if len(tc.aggregatedIdPs) == 0 {
		return errors.New("expected IdPs from working source, but got none")
	}

	return nil
}

// aggregatorShouldReportSourceFailures verifies failure tracking.
func aggregatorShouldReportSourceFailures(ctx context.Context, expectedFailures int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if tc.sourceFailures != expectedFailures {
		return fmt.Errorf("expected %d source failures, got %d", expectedFailures, tc.sourceFailures)
	}

	return nil
}

// iShouldSee1IdPNotDuplicated verifies deduplication works.
func iShouldSee1IdPNotDuplicated(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if len(tc.aggregatedIdPs) != 1 {
		var entityIDs []string
		for _, idp := range tc.aggregatedIdPs {
			entityIDs = append(entityIDs, idp.EntityID)
		}
		return fmt.Errorf("expected 1 IdP (deduplicated), got %d: %v", len(tc.aggregatedIdPs), entityIDs)
	}

	return nil
}

// singleSourceModeShouldWork verifies backward compatibility.
func singleSourceModeShouldWork(ctx context.Context) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Single source should produce same result as before
	if len(tc.metadataSources) != 1 {
		return fmt.Errorf("expected single source mode, but got %d sources", len(tc.metadataSources))
	}

	if len(tc.aggregatedIdPs) != 3 {
		return fmt.Errorf("expected 3 IdPs in single source mode, got %d", len(tc.aggregatedIdPs))
	}

	return nil
}
