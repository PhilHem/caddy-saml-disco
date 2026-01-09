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

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// testContext holds the test state for each scenario.
type testContext struct {
	// Raw IdPs from Background step (populated via table)
	allIdPs []domain.IdPInfo

	// Config from Given steps
	idpFilter     string
	loginRedirect string

	// Computed at "When" time
	filteredIdPs []domain.IdPInfo

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
func iShouldSeeNIdPs(ctx context.Context, expectedCount int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	actualCount := len(tc.filteredIdPs)
	if actualCount != expectedCount {
		var entityIDs []string
		for _, idp := range tc.filteredIdPs {
			entityIDs = append(entityIDs, idp.EntityID)
		}
		return fmt.Errorf("expected %d IdP(s), got %d: %v", expectedCount, actualCount, entityIDs)
	}

	return nil
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
