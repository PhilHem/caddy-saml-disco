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

  Scenario: Single glob pattern filters by suffix
    Given idp_filter configured as "*.example.edu"
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
    Given idp_filter configured as "https://idp3.other.com/saml, *.example.edu"
    When I list available IdPs
    Then I should see 2 IdPs
    And I should see "https://idp1.example.edu/saml"
    And I should see "https://idp3.other.com/saml"

  Scenario: Empty filter returns all IdPs
    Given idp_filter is not configured
    When I list available IdPs
    Then I should see 3 IdPs
