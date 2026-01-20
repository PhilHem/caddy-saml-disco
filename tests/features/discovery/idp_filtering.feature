Feature: IdP Filtering for Discovery
  As a service administrator
  I want to filter which IdPs are available for discovery
  So that users only see relevant identity providers

  Background:
    Given metadata with IdPs:
      | entityID                        |
      | https://idp1.example.edu/saml   |
      | https://idp2.example.org/saml   |
      | https://idp3.other.com/saml     |

  Scenario: Single glob pattern filters by domain substring
    Given idp_filter configured as "*example.edu*"
    When I list available IdPs
    Then I should see 1 IdP
    And I should see "https://idp1.example.edu/saml"

  Scenario: Multiple exact entity IDs act as whitelist
    Given idp_filter configured as "https://idp1.example.edu/saml, https://idp2.example.org/saml"
    When I list available IdPs
    Then I should see 2 IdPs
    And I should see "https://idp1.example.edu/saml"
    And I should see "https://idp2.example.org/saml"
    And I should not see "https://idp3.other.com/saml"

  Scenario: Mixed patterns and exact matches
    Given idp_filter configured as "https://idp3.other.com/saml, *example.edu*"
    When I list available IdPs
    Then I should see 2 IdPs
    And I should see "https://idp1.example.edu/saml"
    And I should see "https://idp3.other.com/saml"

  Scenario: Empty filter returns all IdPs
    Given idp_filter is not configured
    When I list available IdPs
    Then I should see 3 IdPs

  Scenario: Multiple metadata sources with different filters
    Given metadata sources:
      | source_type | location                        | idp_filter         |
      | url         | https://federation1.example/xml | *example.edu*      |
      | url         | https://federation2.example/xml |                    |
      | file        | /etc/saml/local-idps.xml        | *example.org*      |
    When I aggregate metadata from all sources
    Then I should see IdPs from all sources
    And deduplicated IdPs count is 3

  Scenario: Fallback when one source fails
    Given metadata sources:
      | source_type | location                        | status |
      | url         | https://federation1.example/xml | error  |
      | url         | https://federation2.example/xml | ok     |
    When I aggregate metadata from all sources
    Then I should see IdPs from the working source
    And the aggregator should report 1 source failure

  Scenario: Deduplication across sources
    Given metadata sources:
      | source_type | location                        | idp_filter |
      | url         | https://federation1.example/xml |            |
      | url         | https://federation2.example/xml |            |
    And both sources contain "https://idp1.example.edu/saml"
    When I aggregate metadata from all sources
    Then I should see 1 IdP (not duplicated)

  Scenario: Backward compatibility with single source
    Given metadata sources:
      | source_type | location                 |
      | url         | https://metadata.example |
    When I aggregate metadata from all sources
    Then I should see 3 IdPs
    And single source mode should work without code changes
