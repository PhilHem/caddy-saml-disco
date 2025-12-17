# Local Entitlements Example

This example demonstrates file-based authorization using local entitlements. Users are authenticated via SAML, then authorized based on entries in `entitlements.json` or `entitlements.yaml`.

## Overview

The `caddy-saml-disco` plugin supports lightweight file-based authorization for small internal services without external infrastructure. This enables:

- **Simple access control** without external authorization services
- **Pattern-based matching** for groups of users (`*@example.edu`, `staff@*`)
- **Role-based access control** with HTTP header injection
- **Hot-reload** of entitlements without restarting Caddy
- **Combined authorization** - local entitlements supplement SAML attributes from IdP

## When to Use Local Entitlements

### ✅ Good For:

- Small deployments (< 100 users)
- Internal services with simple access control needs
- Environments without external authorization infrastructure
- Quick prototyping and development
- Combining IdP-provided attributes with local overrides

### ❌ Not Recommended For:

- Large-scale deployments (1000+ users)
- Complex authorization policies requiring external data
- High-frequency entitlement changes (use external API instead)
- Multi-tenant systems with dynamic user management
- Environments requiring audit trails or compliance reporting

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│  1. User authenticates via SAML (IdP provides subject)          │
│                        ↓                                        │
│  2. Plugin looks up subject in entitlements.json               │
│     - Exact match: admin@example.edu                            │
│     - Pattern match: *@example.edu, staff@*                    │
│                        ↓                                        │
│  3. If found (or default_action=allow):                        │
│     - Check require_entitlement (if configured)                  │
│     - Inject roles/metadata as HTTP headers                     │
│     - Allow access to protected route                           │
│                        ↓                                        │
│  4. If not found AND default_action=deny:                       │
│     - Redirect to entitlement_deny_redirect (or 403)            │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File                | Purpose                                       |
| ------------------- | --------------------------------------------- |
| `Caddyfile`         | Configuration showing entitlements directives |
| `entitlements.json` | Sample entitlements file (JSON format)        |
| `entitlements.yaml` | Sample entitlements file (YAML format)        |

## Entitlements File Structure

### JSON Format (`entitlements.json`)

```json
{
  "default_action": "deny",
  "entries": [
    {
      "subject": "admin@example.edu",
      "roles": ["admin", "staff"],
      "metadata": {
        "department": "IT",
        "access_level": "full"
      }
    },
    {
      "pattern": "*@example.edu",
      "roles": ["user"]
    },
    {
      "pattern": "staff@*",
      "roles": ["staff"]
    }
  ]
}
```

### YAML Format (`entitlements.yaml`)

```yaml
default_action: deny
entries:
  - subject: admin@example.edu
    roles: [admin, staff]
    metadata:
      department: IT
      access_level: full
  - pattern: "*@example.edu"
    roles: [user]
  - pattern: "staff@*"
    roles: [staff]
```

### Fields

- **`default_action`**: `"deny"` (allowlist) or `"allow"` (blocklist)
- **`entries`**: Array of entitlement entries
  - **`subject`**: Exact match (e.g., `"admin@example.edu"`)
  - **`pattern`**: Glob pattern (e.g., `"*@example.edu"`, `"staff@*"`)
  - **`roles`**: Array of role strings (e.g., `["admin", "staff"]`)
  - **`metadata`**: Key-value pairs for header injection

**Note**: Each entry must have either `subject` OR `pattern`, not both.

## Configuration

### Basic Setup

```caddyfile
saml_disco {
    entity_id https://myapp.example.com/saml
    metadata_file /etc/caddy/saml/idp-metadata.xml
    cert_file /etc/caddy/saml/sp-cert.pem
    key_file /etc/caddy/saml/sp-key.pem

    # Enable local entitlements
    entitlements_file ./entitlements.json
    entitlements_refresh_interval 5m
}
```

### Entitlement Headers

Map entitlement fields to HTTP headers for downstream handlers:

```caddyfile
entitlement_headers {
    roles X-Entitlement-Roles ;
    department X-Department
}
```

- **`roles`**: Maps `roles` array to header (separator: `;`)
- **`department`**: Maps `metadata.department` to header
- Separator defaults to `;` if omitted

### Route Protection

Require specific role for all routes:

```caddyfile
require_entitlement admin
```

Users without `admin` role are denied access (redirected or 403).

### Custom Deny Redirect

```caddyfile
entitlement_deny_redirect /unauthorized
```

Unauthorized users are redirected to `/unauthorized` instead of receiving 403.

## Access Control Modes

### Allowlist Mode (`default_action: deny`)

Only users listed in entitlements file can access:

```json
{
  "default_action": "deny",
  "entries": [
    { "subject": "admin@example.edu", "roles": ["admin"] },
    { "pattern": "*@example.edu", "roles": ["user"] }
  ]
}
```

- `admin@example.edu` → allowed (has `admin` role)
- `user@example.edu` → allowed (has `user` role)
- `external@other.com` → **denied** (not in file)

### Blocklist Mode (`default_action: allow`)

All authenticated users allowed, except those matching patterns:

```json
{
  "default_action": "allow",
  "entries": [{ "pattern": "contractor@*", "roles": ["contractor"] }]
}
```

- `user@example.edu` → allowed (no match, default action)
- `contractor@temp.com` → allowed (has `contractor` role, but still allowed)
- All users get their roles injected as headers

**Note**: In blocklist mode, `require_entitlement` still applies - users must have the required role.

## Pattern Matching

Patterns use glob syntax:

- `*@example.edu` - Matches any user from `example.edu` domain
- `staff@*` - Matches any user with `staff@` prefix
- `*admin*` - Matches any subject containing `admin`
- `exact@match.com` - Exact match (use `subject` instead)

Patterns are checked in order - first match wins.

## Quick Start

1. Copy `entitlements.json` to your Caddy configuration directory
2. Copy and customize the `Caddyfile`
3. Update paths in `Caddyfile`:
   - `entitlements_file` - path to your entitlements file
   - `metadata_file` - path to IdP metadata
   - `cert_file` / `key_file` - SP credentials
4. Run Caddy: `caddy run --config Caddyfile`

## Verification Checklist

Use these scenarios to verify the example works correctly:

| #   | Scenario               | Steps                                                        | Expected Result                                                   |
| --- | ---------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------- |
| 1   | Admin access           | Authenticate as `admin@example.edu`, visit `/admin`          | Access granted, `X-Entitlement-Roles: admin;staff` header present |
| 2   | Regular user access    | Authenticate as `user@example.edu`, visit `/admin`           | Redirected to `/unauthorized` (or 403)                            |
| 3   | Pattern matching       | Authenticate as `staff@anywhere.com`, visit public route     | Access granted, `X-Entitlement-Roles: staff` header present       |
| 4   | Header injection       | Authenticate as `admin@example.edu`, check request headers   | `X-Entitlement-Roles: admin;staff` and `X-Department: IT` present |
| 5   | Allowlist mode         | Authenticate as `external@other.com`                         | Access denied (not in entitlements file)                          |
| 6   | File reload            | Edit `entitlements.json`, wait for refresh interval          | Changes take effect without restarting Caddy                      |
| 7   | Exact match precedence | Authenticate as `admin@example.edu`                          | Gets `admin` role (exact match), not `user` role (pattern match)  |
| 8   | Blocklist mode         | Change `default_action` to `allow`, authenticate as any user | All users allowed (unless `require_entitlement` blocks them)      |

## Combining with SAML Attributes

Local entitlements are combined with SAML attributes from the IdP:

```caddyfile
# SAML attributes from IdP
attribute_headers {
    mail X-Remote-User
    displayName X-Display-Name
}

# Local entitlements
entitlement_headers {
    roles X-Entitlement-Roles
    department X-Department
}
```

Both sets of headers are injected - local entitlements supplement (not replace) IdP attributes.

## Advanced Usage

### Per-Route Entitlement Checking

Instead of global `require_entitlement`, check headers in your application:

```caddyfile
handle /admin/* {
    reverse_proxy localhost:8080 {
        header_up X-Entitlement-Roles {http.request.header.X-Entitlement-Roles}
    }
}
```

Your application checks `X-Entitlement-Roles` header for `admin` role.

### Multiple Entitlement Files

Use different files for different SP configs (multi-SP mode):

```caddyfile
sp admin.example.com {
    entitlements_file ./entitlements-admin.json
}

sp user.example.com {
    entitlements_file ./entitlements-users.json
}
```

## Troubleshooting

### Users Not Getting Roles

1. Check subject matches exactly (case-sensitive)
2. Verify pattern syntax (`*@example.edu`, not `*@example.edu*`)
3. Check file reload interval (default: 5m)
4. Verify `entitlement_headers` mapping matches field names

### Access Denied Unexpectedly

1. Check `default_action` - `deny` means only listed users allowed
2. Verify `require_entitlement` matches a role in entitlements file
3. Check pattern matching order (exact matches checked first)
4. Verify subject format matches IdP NameID format

### Headers Not Injected

1. Verify `entitlement_headers` block is configured
2. Check header names start with `X-`
3. Verify field names match (`roles`, `department`, etc.)
4. Check downstream handler receives headers (may be stripped by proxy)

## Security Considerations

- **File permissions**: Restrict read access to entitlements file (chmod 600)
- **Pattern validation**: Avoid ReDoS-prone patterns (fuzz tests verify this)
- **Header injection**: Entitlement values are sanitized before header injection
- **Hot-reload**: File changes are atomic (no partial reads during reload)
- **Concurrent access**: Lookups are thread-safe (read locks)

## See Also

- [Main README](../../README.md) - Full plugin documentation
- [Custom UI Example](../custom-ui/README.md) - Custom discovery UI example
- [Caddyfile Reference](../../docs/CADDYFILE.md) - Complete directive reference



