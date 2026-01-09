Feature: IdP Filter Failure Observability
  As a system administrator
  I want filter failures to include available IdP information
  So that I can diagnose configuration mismatches quickly

  Background:
    Given metadata with IdPs:
      | entityID                                |
      | https://idp.uni-mannheim.de/shibboleth  |
      | https://idp-test.uni-mannheim.de/shib   |

  Scenario: Filter mismatch includes available IdPs in error message
    Given idp_filter configured as "*nomatch*"
    When metadata is loaded
    Then the error message should contain "available:"
    And the error message should contain "https://idp.uni-mannheim.de/shibboleth"

  Scenario: Filter mismatch produces structured warning log
    Given idp_filter configured as "*nomatch*"
    And structured logging is enabled
    When metadata is loaded
    Then a warning log should contain field "idps_before_filter" with value 2
    And the log should contain field "available_entity_ids"
    And the log should contain field "filter_failures"

  Scenario: Large IdP list is truncated in error message
    Given metadata with 100 IdPs
    And idp_filter configured as "*nomatch*"
    When metadata is loaded
    Then the error message should contain "and 95 more"

  Scenario: Structured log includes up to 10 entity IDs
    Given metadata with 100 IdPs
    And idp_filter configured as "*nomatch*"
    And structured logging is enabled
    When metadata is loaded
    Then the warning log field "available_entity_ids" should have at most 10 entries
