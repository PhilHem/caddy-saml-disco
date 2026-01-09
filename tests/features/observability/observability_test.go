//go:build bdd

package observability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	caddy "github.com/philiph/caddy-saml-disco/internal/adapters/driving/caddy"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// testContext holds the test state for each scenario.
type testContext struct {
	// Logger observation
	logCore     zapcore.Core
	logObserver *observer.ObservedLogs
	logger      *zap.Logger

	// Metrics
	registry        *prometheus.Registry
	metricsRecorder *metrics.PrometheusMetricsRecorder

	// Test data for SAML auth error scenarios
	idpEntityID  string
	errorDetails *caddy.SAMLErrorDetails

	// Test data for filter failure scenarios
	idps      []domain.IdPInfo // IdPs to load
	idpFilter string           // Filter pattern to apply
	loadError error            // Error from metadata loading
}

// ctxKey is the context key for testContext.
type ctxKey struct{}

func TestFeatures(t *testing.T) {
	tra.Require(t, "Adapter.Observability.SAMLAuthErrors")

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
	// Before each scenario: set up fresh observability infrastructure
	sc.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		tc := &testContext{
			idpEntityID: "https://default-idp.example.com",
		}

		// Set up zap observer for log capture
		core, logs := observer.New(zap.WarnLevel)
		tc.logCore = core
		tc.logObserver = logs
		tc.logger = zap.New(core)

		// Set up Prometheus registry for metrics capture
		tc.registry = prometheus.NewRegistry()
		tc.metricsRecorder = metrics.NewPrometheusMetricsRecorderWithRegistry(tc.registry)

		return context.WithValue(ctx, ctxKey{}, tc), nil
	})

	// Background step
	sc.Step(`^a configured observability context$`, aConfiguredObservabilityContext)

	// Given steps
	sc.Step(`^an IdP with entity ID "([^"]*)"$`, anIdPWithEntityID)

	// When steps - auth failure triggers
	sc.Step(`^a SAML authentication fails due to signature verification$`, authFailsDueToSignatureVerification)
	sc.Step(`^a SAML authentication fails due to decryption failure$`, authFailsDueToDecryptionFailure)
	sc.Step(`^a SAML authentication fails due to time constraint violation$`, authFailsDueToTimeConstraint)
	sc.Step(`^a SAML authentication fails due to IdP status error$`, authFailsDueToIdPStatus)
	sc.Step(`^a SAML authentication fails due to an unknown error$`, authFailsDueToUnknownError)

	// Then steps - log assertions
	sc.Step(`^a warning log should contain field "([^"]*)" with value "([^"]*)"$`, aWarningLogShouldContainFieldWithValue)
	sc.Step(`^the log should contain field "([^"]*)"$`, theLogShouldContainField)

	// Then steps - metric assertions
	sc.Step(`^metric "([^"]*)" should be incremented$`, metricShouldBeIncremented)
	sc.Step(`^the metric should have label "([^"]*)" with value "([^"]*)"$`, theMetricShouldHaveLabelWithValue)
	sc.Step(`^metric "([^"]*)" should have label "([^"]*)" with value "([^"]*)"$`, metricShouldHaveLabelWithValue)

	// Filter failure scenario steps
	sc.Step(`^metadata with IdPs:$`, metadataWithIdPs)
	sc.Step(`^idp_filter configured as "([^"]*)"$`, idpFilterConfiguredAs)
	sc.Step(`^metadata with (\d+) IdPs$`, metadataWithNIdPs)
	sc.Step(`^structured logging is enabled$`, structuredLoggingIsEnabled)
	sc.Step(`^metadata is loaded$`, metadataIsLoaded)
	sc.Step(`^the error message should contain "([^"]*)"$`, errorMessageShouldContain)
	sc.Step(`^the warning log field "([^"]*)" should have at most (\d+) entries$`, warningLogFieldShouldHaveAtMostEntries)
	sc.Step(`^a warning log should contain field "([^"]*)" with value (\d+)$`, aWarningLogShouldContainFieldWithIntValue)
}

// Background step implementation
func aConfiguredObservabilityContext(ctx context.Context) error {
	// The Before hook already sets up the context
	tc := ctx.Value(ctxKey{}).(*testContext)
	if tc == nil {
		return errors.New("test context not initialized")
	}
	return nil
}

// Given step implementations
func anIdPWithEntityID(ctx context.Context, entityID string) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.idpEntityID = entityID
	return ctx, nil
}

// When step implementations - these simulate what the ACS handler does
func authFailsDueToSignatureVerification(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Create a signature verification error
	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("signature verification failed"),
		Now:        time.Now(),
	}

	// Parse and process the error (simulating what the ACS handler does)
	tc.errorDetails = caddy.ParseSAMLError(err)

	// Emit log with structured fields (simulating handler behavior)
	fields := buildLogFields(tc.errorDetails, tc.idpEntityID)
	tc.logger.Warn("saml authentication failed", fields...)

	// Record metric
	tc.metricsRecorder.RecordAuthFailure(string(tc.errorDetails.Category), tc.idpEntityID)

	return ctx, nil
}

func authFailsDueToDecryptionFailure(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("failed to decrypt assertion"),
		Now:        time.Now(),
	}

	tc.errorDetails = caddy.ParseSAMLError(err)
	fields := buildLogFields(tc.errorDetails, tc.idpEntityID)
	tc.logger.Warn("saml authentication failed", fields...)
	tc.metricsRecorder.RecordAuthFailure(string(tc.errorDetails.Category), tc.idpEntityID)

	return ctx, nil
}

func authFailsDueToTimeConstraint(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("assertion NotOnOrAfter has passed"),
		Now:        time.Now(),
	}

	tc.errorDetails = caddy.ParseSAMLError(err)
	fields := buildLogFields(tc.errorDetails, tc.idpEntityID)
	tc.logger.Warn("saml authentication failed", fields...)
	tc.metricsRecorder.RecordAuthFailure(string(tc.errorDetails.Category), tc.idpEntityID)

	return ctx, nil
}

func authFailsDueToIdPStatus(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	responseXML := `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
    <samlp:StatusMessage>User denied access</samlp:StatusMessage>
  </samlp:Status>
</samlp:Response>`

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("bad status code"),
		Response:   responseXML,
		Now:        time.Now(),
	}

	tc.errorDetails = caddy.ParseSAMLError(err)
	fields := buildLogFields(tc.errorDetails, tc.idpEntityID)
	tc.logger.Warn("saml authentication failed", fields...)
	tc.metricsRecorder.RecordAuthFailure(string(tc.errorDetails.Category), tc.idpEntityID)

	return ctx, nil
}

func authFailsDueToUnknownError(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	err := &saml.InvalidResponseError{
		PrivateErr: errors.New("some unexpected error occurred"),
		Now:        time.Now(),
	}

	tc.errorDetails = caddy.ParseSAMLError(err)
	fields := buildLogFields(tc.errorDetails, tc.idpEntityID)
	tc.logger.Warn("saml authentication failed", fields...)
	tc.metricsRecorder.RecordAuthFailure(string(tc.errorDetails.Category), tc.idpEntityID)

	return ctx, nil
}

// Then step implementations - log assertions
func aWarningLogShouldContainFieldWithValue(ctx context.Context, fieldName, expectedValue string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)
	logs := tc.logObserver.All()
	if len(logs) == 0 {
		return errors.New("no logs captured")
	}

	// Find the most recent warning log
	var targetLog *observer.LoggedEntry
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Level == zap.WarnLevel {
			targetLog = &logs[i]
			break
		}
	}

	if targetLog == nil {
		return errors.New("no warning log found")
	}

	fields := targetLog.ContextMap()
	actualValue, ok := fields[fieldName]
	if !ok {
		return fmt.Errorf("expected field %q not found in log; available fields: %v", fieldName, getFieldNames(fields))
	}

	if fmt.Sprintf("%v", actualValue) != expectedValue {
		return fmt.Errorf("field %q has value %q, expected %q", fieldName, actualValue, expectedValue)
	}

	return nil
}

func theLogShouldContainField(ctx context.Context, fieldName string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)
	logs := tc.logObserver.All()
	if len(logs) == 0 {
		return errors.New("no logs captured")
	}

	// Find the most recent warning log
	var targetLog *observer.LoggedEntry
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Level == zap.WarnLevel {
			targetLog = &logs[i]
			break
		}
	}

	if targetLog == nil {
		return errors.New("no warning log found")
	}

	fields := targetLog.ContextMap()
	if _, ok := fields[fieldName]; !ok {
		return fmt.Errorf("expected field %q not found in log; available fields: %v", fieldName, getFieldNames(fields))
	}

	return nil
}

// aWarningLogShouldContainFieldWithIntValue asserts a field has an integer value.
// Then step: Then a warning log should contain field "idps_before_filter" with value 2
func aWarningLogShouldContainFieldWithIntValue(ctx context.Context, fieldName string, expectedValue int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)
	logs := tc.logObserver.All()
	if len(logs) == 0 {
		return errors.New("no logs captured")
	}

	// Find the most recent warning log
	var targetLog *observer.LoggedEntry
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Level == zap.WarnLevel {
			targetLog = &logs[i]
			break
		}
	}

	if targetLog == nil {
		return errors.New("no warning log found")
	}

	fields := targetLog.ContextMap()
	actualValue, ok := fields[fieldName]
	if !ok {
		return fmt.Errorf("expected field %q not found in log; available fields: %v", fieldName, getFieldNames(fields))
	}

	// Handle various numeric types that zap might use
	var actualInt int64
	switch v := actualValue.(type) {
	case int:
		actualInt = int64(v)
	case int64:
		actualInt = v
	case int32:
		actualInt = int64(v)
	case float64:
		actualInt = int64(v)
	default:
		return fmt.Errorf("field %q has non-numeric type %T, expected integer", fieldName, actualValue)
	}

	if actualInt != int64(expectedValue) {
		return fmt.Errorf("field %q has value %d, expected %d", fieldName, actualInt, expectedValue)
	}

	return nil
}

// Then step implementations - metric assertions
func metricShouldBeIncremented(ctx context.Context, metricName string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	metricFamilies, err := tc.registry.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	for _, mf := range metricFamilies {
		if mf.GetName() == metricName {
			for _, m := range mf.GetMetric() {
				if m.GetCounter().GetValue() > 0 {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("metric %q not found or not incremented", metricName)
}

func theMetricShouldHaveLabelWithValue(ctx context.Context, labelName, expectedValue string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	metricFamilies, err := tc.registry.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	// Look for the auth failures metric
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_auth_failures_total" {
			for _, m := range mf.GetMetric() {
				for _, label := range m.GetLabel() {
					if label.GetName() == labelName && label.GetValue() == expectedValue {
						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("metric label %q with value %q not found", labelName, expectedValue)
}

func metricShouldHaveLabelWithValue(ctx context.Context, metricName, labelName, expectedValue string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	metricFamilies, err := tc.registry.Gather()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	for _, mf := range metricFamilies {
		if mf.GetName() == metricName {
			for _, m := range mf.GetMetric() {
				for _, label := range m.GetLabel() {
					if label.GetName() == labelName && label.GetValue() == expectedValue {
						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("metric %q label %q with value %q not found", metricName, labelName, expectedValue)
}

// buildLogFields mirrors the logging logic in plugin.go handleACSError
func buildLogFields(details *caddy.SAMLErrorDetails, idpEntityID string) []zap.Field {
	fields := []zap.Field{
		zap.String("error_category", string(details.Category)),
		zap.String("idp_entity_id", idpEntityID),
	}
	if details.PrivateError != "" {
		fields = append(fields, zap.String("private_error", details.PrivateError))
	}
	if details.IdPStatus != nil {
		fields = append(fields, zap.String("idp_status_code", details.IdPStatus.StatusCode))
		if details.IdPStatus.StatusMessage != "" {
			fields = append(fields, zap.String("idp_status_message", details.IdPStatus.StatusMessage))
		}
	}
	if details.TimeContext != nil {
		fields = append(fields, zap.Time("server_time", details.TimeContext.ServerTime))
	}
	return fields
}

// getFieldNames returns the field names from a map for error messages
func getFieldNames(fields map[string]interface{}) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	return names
}

// =============================================================================
// Filter Failure Step Implementations
// =============================================================================

// metadataWithIdPs populates the test context with IdPs from a Gherkin table.
// Background step: Given metadata with IdPs:
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
		tc.idps = append(tc.idps, domain.IdPInfo{
			EntityID:    entityID,
			DisplayName: entityID, // Use entity ID as display name for simplicity
		})
	}

	return ctx, nil
}

// idpFilterConfiguredAs sets the filter pattern for the scenario.
// Given step: Given idp_filter configured as "*nomatch*"
func idpFilterConfiguredAs(ctx context.Context, pattern string) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)
	tc.idpFilter = pattern
	return ctx, nil
}

// metadataWithNIdPs generates N test IdPs for large dataset scenarios.
// Given step: Given metadata with 100 IdPs
func metadataWithNIdPs(ctx context.Context, count int) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Clear any existing IdPs (this step overrides background)
	tc.idps = nil

	// Generate N IdPs with sequential entity IDs
	for i := 1; i <= count; i++ {
		tc.idps = append(tc.idps, domain.IdPInfo{
			EntityID:    fmt.Sprintf("https://idp-%03d.example.com/shibboleth", i),
			DisplayName: fmt.Sprintf("Test IdP %d", i),
		})
	}

	return ctx, nil
}

// structuredLoggingIsEnabled is a no-op since logging is enabled in Before hook.
// Given step: Given structured logging is enabled
func structuredLoggingIsEnabled(ctx context.Context) (context.Context, error) {
	// Already enabled via Before hook - this step exists for documentation
	return ctx, nil
}

// metadataIsLoaded applies the filter and captures errors/logs.
// When step: When metadata is loaded
func metadataIsLoaded(ctx context.Context) (context.Context, error) {
	tc := ctx.Value(ctxKey{}).(*testContext)

	// Capture original entity IDs before filtering (mirrors FileMetadataStore.Refresh behavior)
	originalEntityIDs := domain.ExtractEntityIDs(tc.idps)

	// Apply filter using the metadata package's exported function
	// This simulates what happens during FileMetadataStore.Refresh()
	filtered, filterFailures := metadata.ApplyFiltersAndCollectFailures(
		tc.idps,
		tc.idpFilter,
		"",        // registrationAuthorityFilter
		"",        // entityCategoryFilter
		"",        // assuranceCertificationFilter
		tc.logger, // Pass logger for structured logging
	)

	// If filter failures occurred, build the error using FormatFilterError
	// (mirrors FileMetadataStore.Refresh behavior)
	if len(filterFailures) > 0 {
		tc.loadError = fmt.Errorf("%s", domain.FormatFilterError(filterFailures, originalEntityIDs))
	} else if len(filtered) == 0 {
		tc.loadError = errors.New("no IdPs found in metadata")
	}

	return ctx, nil
}

// errorMessageShouldContain asserts that the load error contains the expected text.
// Then step: Then the error message should contain "available:"
func errorMessageShouldContain(ctx context.Context, expected string) error {
	tc := ctx.Value(ctxKey{}).(*testContext)

	if tc.loadError == nil {
		return errors.New("expected an error but none occurred")
	}

	errMsg := tc.loadError.Error()
	if !strings.Contains(errMsg, expected) {
		return fmt.Errorf("error message %q does not contain %q", errMsg, expected)
	}

	return nil
}

// warningLogFieldShouldHaveAtMostEntries asserts that a log field array has at most N entries.
// Then step: Then the warning log field "available_entity_ids" should have at most 10 entries
func warningLogFieldShouldHaveAtMostEntries(ctx context.Context, fieldName string, maxEntries int) error {
	tc := ctx.Value(ctxKey{}).(*testContext)
	logs := tc.logObserver.All()

	if len(logs) == 0 {
		return errors.New("no logs captured")
	}

	// Find the most recent warning log
	var targetLog *observer.LoggedEntry
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Level == zap.WarnLevel {
			targetLog = &logs[i]
			break
		}
	}

	if targetLog == nil {
		return errors.New("no warning log found")
	}

	fields := targetLog.ContextMap()
	fieldValue, ok := fields[fieldName]
	if !ok {
		return fmt.Errorf("field %q not found in log; available fields: %v", fieldName, getFieldNames(fields))
	}

	// Handle array type
	switch v := fieldValue.(type) {
	case []interface{}:
		if len(v) > maxEntries {
			return fmt.Errorf("field %q has %d entries, expected at most %d", fieldName, len(v), maxEntries)
		}
	case []string:
		if len(v) > maxEntries {
			return fmt.Errorf("field %q has %d entries, expected at most %d", fieldName, len(v), maxEntries)
		}
	default:
		return fmt.Errorf("field %q is not an array type, got %T", fieldName, fieldValue)
	}

	return nil
}

// Ensure domain package is used (for SAMLErrorCategory reference in documentation)
var _ = domain.SAMLErrUnknown
