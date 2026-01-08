//go:build bdd

package observability

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

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

	// Test data
	idpEntityID  string
	errorDetails *caddy.SAMLErrorDetails
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

// Ensure domain package is used (for SAMLErrorCategory reference in documentation)
var _ = domain.SAMLErrUnknown
