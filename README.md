# caddy-saml-disco

A Caddy v2 plugin providing SAML Service Provider (SP) authentication with IdP Discovery Service support.

## Features

- **SAML SP Authentication** - Protect any Caddy route with SAML-based SSO
- **IdP Discovery Service** - Built-in UI for selecting from multiple Identity Providers
- **Federation Support** - Load metadata aggregates (e.g., eduGAIN, InCommon)
- **JSON API** - Build custom login UIs with the discovery API
- **Cookie Sessions** - JWT-based sessions stored in secure HTTP cookies
- **Metadata Signature Verification** - Validate federation metadata signatures

## Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/philhem/caddy-saml-disco/releases):

```bash
# Linux (amd64)
curl -LO https://github.com/philhem/caddy-saml-disco/releases/latest/download/caddy-saml-disco-linux-amd64.tar.gz
tar xzf caddy-saml-disco-linux-amd64.tar.gz
sudo mv caddy /usr/local/bin/

# Linux (arm64)
curl -LO https://github.com/philhem/caddy-saml-disco/releases/latest/download/caddy-saml-disco-linux-arm64.tar.gz

# macOS (Apple Silicon)
curl -LO https://github.com/philhem/caddy-saml-disco/releases/latest/download/caddy-saml-disco-darwin-arm64.tar.gz
```

### Docker

```bash
docker pull ghcr.io/philhem/caddy-saml-disco:latest
```

### Build from Source

Using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/philhem/caddy-saml-disco
```

### Verifying Installation

Check that the plugin is installed and view version info:

```bash
caddy version
```

Output includes the plugin version:

```
v2.8.4 h1:...
  ...
  github.com/philhem/caddy-saml-disco v0.9.1
```

## Quick Start: Single IdP Deployment

This guide covers the most common deployment: protecting an application with SAML authentication using a single Identity Provider.

### Prerequisites

1. **An Identity Provider** - Your organization's IdP (Okta, Azure AD, Keycloak, Shibboleth, etc.)
2. **IdP Metadata** - XML file or URL from your IdP
3. **SP Certificate/Key** - X.509 certificate pair for signing SAML requests

### Step 1: Generate SP Certificates

Create a self-signed certificate for your Service Provider:

```bash
openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem -out sp-cert.pem \
  -days 3650 -nodes -subj "/CN=myapp.example.com"
```

### Step 2: Get IdP Metadata

Download your IdP's metadata XML. Common locations:

| IdP | Typical Metadata URL |
|-----|---------------------|
| Okta | `https://{yourorg}.okta.com/app/{app-id}/sso/saml/metadata` |
| Azure AD | `https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml` |
| Keycloak | `https://{host}/realms/{realm}/protocol/saml/descriptor` |
| Shibboleth | `https://{host}/idp/shibboleth` |

Save it locally or use the URL directly in configuration.

### Step 3: Register Your SP with the IdP

Your IdP needs to know about your Service Provider. Provide:

- **Entity ID**: `https://myapp.example.com/saml` (or your chosen identifier)
- **ACS URL**: `https://myapp.example.com/saml/acs`
- **SP Metadata**: Available at `https://myapp.example.com/saml/metadata` after deployment

### Step 4: Create Caddyfile

```caddyfile
myapp.example.com {
    saml_disco {
        # SP identity (must match IdP configuration)
        entity_id https://myapp.example.com/saml

        # IdP metadata (use URL or local file)
        metadata_url https://idp.example.com/metadata
        # Or: metadata_file /etc/caddy/idp-metadata.xml

        # SP certificates
        cert_file /etc/caddy/sp-cert.pem
        key_file /etc/caddy/sp-key.pem

        # Session duration (optional, default: 8h)
        session_duration 4h
    }

    # Your protected application
    reverse_proxy localhost:8080
}
```

### Step 5: Run Caddy

```bash
caddy run --config Caddyfile
```

Or with Docker:

```bash
docker run -d \
  -p 80:80 -p 443:443 \
  -v ./Caddyfile:/etc/caddy/Caddyfile \
  -v ./sp-cert.pem:/etc/caddy/sp-cert.pem \
  -v ./sp-key.pem:/etc/caddy/sp-key.pem \
  -v ./idp-metadata.xml:/etc/caddy/idp-metadata.xml \
  -v caddy_data:/data \
  ghcr.io/philhem/caddy-saml-disco:latest
```

### How It Works

1. User visits `https://myapp.example.com/some/page`
2. Plugin detects no valid session
3. User is redirected to IdP for authentication
4. After successful login, IdP redirects to `/saml/acs` with SAML assertion
5. Plugin validates assertion, creates session cookie
6. User is redirected to original URL (`/some/page`)

## Configuration Reference

### Required Options

| Option | Description |
|--------|-------------|
| `entity_id` | SAML entity ID for this SP (must match IdP configuration) |
| `metadata_url` or `metadata_file` | IdP metadata source (exactly one required) |
| `cert_file` | Path to SP certificate (PEM) |
| `key_file` | Path to SP private key (PEM) |

### Session Options

| Option | Default | Description |
|--------|---------|-------------|
| `session_duration` | `8h` | How long sessions last |
| `session_cookie_name` | `saml_session` | Name of the session cookie |

### Metadata Options

| Option | Default | Description |
|--------|---------|-------------|
| `metadata_refresh_interval` | `1h` | How often to refresh metadata |
| `background_refresh` | `false` | Enable periodic background refresh |
| `verify_metadata_signature` | `false` | Verify metadata XML signature |
| `metadata_signing_cert` | - | Federation signing certificate (required if verification enabled) |

### Discovery Options

| Option | Default | Description |
|--------|---------|-------------|
| `idp_filter` | - | Glob pattern to filter IdPs (e.g., `*.example.edu`) |
| `discovery_template` | - | UI template: `""` (default) or `"fels"` |
| `service_name` | - | Service name shown in discovery UI |
| `pinned_idps` | - | List of IdP entity IDs to display prominently |
| `login_redirect` | - | Redirect to custom login page instead of built-in UI |
| `remember_idp_cookie_name` | `saml_last_idp` | Cookie name for remembering last IdP |
| `remember_idp_duration` | `30d` | How long to remember last IdP |
| `default_language` | `en` | Fallback language for display names |

### Advanced Options

| Option | Default | Description |
|--------|---------|-------------|
| `acs_url` | auto-detected | Override Assertion Consumer Service URL |
| `templates_dir` | - | Path to custom template files |
| `cors_allowed_origins` | - | Origins allowed for JSON API CORS |
| `cors_allow_credentials` | `false` | Allow credentials in CORS requests |
| `alt_logins` | - | Alternative login methods (non-SAML) |

## API Endpoints

The plugin exposes these endpoints under the configured route:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | SP metadata XML (share with IdP) |
| `/saml/acs` | POST | Assertion Consumer Service (IdP posts here) |
| `/saml/disco` | GET | Discovery UI (IdP selection page) |
| `/saml/logout` | GET/POST | Clear session and redirect |
| `/saml/api/idps` | GET | List available IdPs (JSON) |
| `/saml/api/idps?q=term` | GET | Search IdPs by name |
| `/saml/api/select` | POST | Select IdP, returns redirect URL |
| `/saml/api/session` | GET | Current session info (JSON) |
| `/saml/api/logo/{entity_id}` | GET | Proxied/cached IdP logo |
| `/saml/api/health` | GET | Health check with metadata status |

### Example: Custom Frontend

Build a custom login UI using the JSON API:

```javascript
// Fetch available IdPs
const response = await fetch('/saml/api/idps?q=university');
const { idps } = await response.json();

// Select an IdP
const selectResponse = await fetch('/saml/api/select', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    entity_id: 'https://idp.example.edu',
    return_to: '/dashboard'
  })
});
const { redirect_url } = await selectResponse.json();
window.location.href = redirect_url;
```

See [`examples/custom-ui/`](examples/custom-ui/) for a complete example.

## Multi-IdP / Federation Deployment

For deployments with multiple IdPs (e.g., research federations):

```caddyfile
federation.example.com {
    saml_disco {
        entity_id https://federation.example.com/saml

        # Load federation metadata aggregate
        metadata_url https://metadata.federation.org/metadata.xml

        # Verify metadata signature
        verify_metadata_signature
        metadata_signing_cert /etc/caddy/federation-signing.pem

        # Background refresh for federation metadata
        background_refresh
        metadata_refresh_interval 30m

        cert_file /etc/caddy/sp-cert.pem
        key_file /etc/caddy/sp-key.pem

        # Optional: Filter to specific IdPs
        idp_filter *.edu

        # Use FeLS-style discovery UI
        discovery_template fels
        service_name "Research Portal"
    }

    reverse_proxy localhost:8080
}
```

## Troubleshooting

### "Invalid SAML Response" Errors

- Verify SP entity ID matches IdP configuration exactly
- Check that IdP metadata is current
- Ensure server clocks are synchronized (SAML is time-sensitive)

### Session Not Persisting

- Verify the domain matches between ACS and protected routes
- Check that cookies are not being blocked
- Ensure `Secure` flag is appropriate for your TLS setup

### Metadata Loading Failures

Check the health endpoint: `curl https://myapp.example.com/saml/api/health`

```json
{
  "status": "healthy",
  "metadata_source": "https://idp.example.com/metadata",
  "idp_count": 1,
  "last_refresh": "2024-01-15T10:30:00Z"
}
```

## License

Apache 2.0
