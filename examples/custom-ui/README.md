# Custom Discovery UI Example

This example demonstrates how to build a custom login/discovery UI that replaces the default embedded template using the JSON API.

## Overview

The `caddy-saml-disco` plugin provides a JSON API that custom frontends can consume instead of using the default HTML template. This enables:

- **Branded UIs** matching your application's design
- **Enhanced UX** with features like autocomplete, favorites, recent IdPs
- **SPA Integration** where the login page is part of a React/Vue/etc app

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  1. User visits /dashboard (protected)                          │
│                        ↓                                        │
│  2. No session → redirect to /login?return_url=/dashboard       │
│                        ↓                                        │
│  3. Custom UI loads, calls GET /saml/api/idps                   │
│                        ↓                                        │
│  4. User selects IdP → POST /saml/api/select                    │
│                        ↓                                        │
│  5. Plugin redirects to IdP for authentication                  │
│                        ↓                                        │
│  6. After auth, user returns to /dashboard                      │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `login.html` | Custom discovery UI (Alpine.js, no build step) |
| `Caddyfile` | Configuration showing `login_redirect` usage |

## API Reference

### GET /saml/api/idps

Returns available identity providers.

**Query Parameters:**
- `q` (optional) - Filter IdPs by display name or entity ID

**Response:**
```json
{
  "idps": [
    {
      "entity_id": "https://idp.example.edu/shibboleth",
      "display_name": "Example University",
      "description": "Research university identity provider",
      "logo_url": "https://idp.example.edu/logo.png",
      "sso_url": "https://idp.example.edu/sso"
    }
  ],
  "remembered_idp_id": "https://idp.example.edu/shibboleth"
}
```

### POST /saml/api/select

Initiates SAML authentication with the selected IdP.

**Request Body:**
```json
{
  "entity_id": "https://idp.example.edu/shibboleth",
  "return_url": "/dashboard"
}
```

**Response:** HTTP 302 redirect to IdP

### GET /saml/api/session

Returns current session information.

**Response (unauthenticated):**
```json
{
  "authenticated": false
}
```

**Response (authenticated):**
```json
{
  "authenticated": true,
  "subject": "user@example.edu",
  "idp_entity_id": "https://idp.example.edu/shibboleth",
  "attributes": {
    "mail": "user@example.edu",
    "displayName": "Jane Doe"
  }
}
```

### GET /saml/logout

Clears session and redirects to `return_to` parameter (defaults to `/`).

## Quick Start

1. Copy `login.html` to your web root (e.g., `/var/www/custom-ui/`)
2. Copy and customize the `Caddyfile`
3. Adjust `login_redirect` to match where you're serving `login.html`
4. Run Caddy

## Verification Checklist

Use these scenarios to verify the example works correctly:

| # | Scenario | Steps | Expected Result |
|---|----------|-------|-----------------|
| 1 | Initial load | Visit `/login` | Spinner appears briefly, then IdP list loads |
| 2 | Search filter | Type institution name in search | Only matching IdPs shown |
| 3 | No results | Search for "xyznonexistent" | "No institutions found" message |
| 4 | Select IdP | Click any IdP card | Overlay shows "Redirecting...", browser navigates to IdP |
| 5 | Preserved return_url | Visit `/login?return_url=/protected`, complete auth | After IdP login, lands on `/protected` |
| 6 | Remembered IdP | After successful login, visit `/login` again | Previously used IdP highlighted at top |
| 7 | Clear remembered | Click "Use a different institution" | Full IdP list shown |
| 8 | Session check | While authenticated, visit `/login` | Shows "Welcome" panel with subject |
| 9 | Logout | Click "Sign Out" button | Session cleared, back to login page |
| 10 | API failure | Stop backend, click "Try Again" | Error message with retry button |
| 11 | Mobile responsive | Resize browser to mobile width | UI remains usable, cards stack |

## Customization

### Styling

The `login.html` uses vanilla CSS. Modify the `<style>` block or replace with your CSS framework (Tailwind, Bootstrap, etc.).

### Branding

- Replace the `<h1>` with your app name/logo
- Adjust colors in CSS variables
- Add your organization's footer/support links

### Enhanced Features

Consider adding:
- Help text explaining what IdPs are
- Support contact for login issues
- Alternative login methods (guest access, etc.)

### SPA Integration

For React/Vue/etc apps, convert the Alpine.js logic to your framework. The API calls remain identical:

```javascript
// React example
const [idps, setIdps] = useState([]);

useEffect(() => {
  fetch('/saml/api/idps')
    .then(r => r.json())
    .then(data => setIdps(data.idps));
}, []);

const selectIdP = async (entityId) => {
  await fetch('/saml/api/select', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entity_id: entityId, return_url: returnUrl })
  });
};
```

## Testing Without SAML

For development, you can test the UI with mock data by modifying `fetchIdPs()`:

```javascript
async fetchIdPs() {
    // Mock data for development
    this.idps = [
        { entity_id: 'test1', display_name: 'Test University 1', description: 'For testing' },
        { entity_id: 'test2', display_name: 'Test University 2', logo_url: 'https://placekitten.com/40/40' }
    ];
    this.filteredIdPs = this.idps;
    this.loading = false;
}
```
