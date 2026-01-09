@beads:caddy-saml-disco-5wz
Feature: Multi-IdP Authentication Redirect
  As a service administrator
  I want unauthenticated users redirected to the discovery page when multiple IdPs match
  So that users can choose their preferred identity provider

  Background:
    Given metadata with IdPs:
      | entityID                            |
      | https://idp1.example.edu/shibboleth |
      | https://idp2.example.edu/shibboleth |
      | https://idp3.other.com/shibboleth   |

  Scenario: Single matching IdP redirects directly to IdP SSO
    Given idp_filter configured as "*other.com*"
    When an unauthenticated request is made to a protected resource
    Then the response should redirect to the IdP SSO endpoint
    And the redirect should include RelayState with the original URL

  Scenario: Multiple matching IdPs redirect to discovery page
    Given idp_filter configured as "*example.edu*"
    When an unauthenticated request is made to a protected resource
    Then the response should redirect to "/saml/disco"
    And the redirect should include return_url with the original URL

  Scenario: No filter configured redirects to discovery when multiple IdPs exist
    Given idp_filter is not configured
    When an unauthenticated request is made to a protected resource
    Then the response should redirect to "/saml/disco"

  Scenario: login_redirect overrides automatic discovery redirect
    Given idp_filter configured as "*example.edu*"
    And login_redirect configured as "/custom-login"
    When an unauthenticated request is made to a protected resource
    Then the response should redirect to "/custom-login"
    And the redirect should include return_url with the original URL
