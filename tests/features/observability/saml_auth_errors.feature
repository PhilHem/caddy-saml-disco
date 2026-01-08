@beads:caddy-saml-disco-s1y
Feature: SAML Authentication Error Observability
  As a system administrator
  I want SAML authentication failures logged with structured context
  And tracked via Prometheus metrics
  So that I can diagnose authentication issues efficiently

  Background:
    Given a configured observability context

  @beads:caddy-saml-disco-do4.1
  Scenario: Signature verification failure produces structured log
    When a SAML authentication fails due to signature verification
    Then a warning log should contain field "error_category" with value "signature_verification"
    And the log should contain field "idp_entity_id"

  @beads:caddy-saml-disco-do4.2
  Scenario: Decryption failure produces structured log
    When a SAML authentication fails due to decryption failure
    Then a warning log should contain field "error_category" with value "decryption_failed"

  @beads:caddy-saml-disco-do4.3
  Scenario: Time constraint failure includes time context
    When a SAML authentication fails due to time constraint violation
    Then a warning log should contain field "error_category" with value "time_constraint"
    And the log should contain field "server_time"

  @beads:caddy-saml-disco-do4.4
  Scenario: IdP status error includes status code
    When a SAML authentication fails due to IdP status error
    Then a warning log should contain field "error_category" with value "idp_status"
    And the log should contain field "idp_status_code"

  @beads:caddy-saml-disco-do4.5
  Scenario: Unknown error categorized correctly
    When a SAML authentication fails due to an unknown error
    Then a warning log should contain field "error_category" with value "unknown"

  @beads:caddy-saml-disco-do4.6
  Scenario: Auth failure increments counter metric
    When a SAML authentication fails due to signature verification
    Then metric "saml_disco_auth_failures_total" should be incremented
    And the metric should have label "reason" with value "signature_verification"

  @beads:caddy-saml-disco-do4.7
  Scenario: Auth failure metric includes IdP entity ID
    Given an IdP with entity ID "https://idp.example.com/saml"
    When a SAML authentication fails due to time constraint violation
    Then metric "saml_disco_auth_failures_total" should have label "idp" with value "https://idp.example.com/saml"
