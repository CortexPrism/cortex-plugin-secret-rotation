# cortex-plugin-secret-rotation

Detect hardcoded secrets, rotate credentials, update Cortex vault.

## Installation

```bash
cortex plugin install marketplace:cortex-plugin-secret-rotation
cortex plugin install github:CortexPrism/cortex-plugin-secret-rotation
cortex plugin install ./manifest.json
```

## Tools

### secrets_scan
Scan a target path for hardcoded secrets.

**Parameters:**
- `target_path` (string, required) — Path to scan
- `patterns` (string, optional) — Comma-separated: aws,github,stripe,gcp,azure,generic
- `exclude_dirs` (string, optional) — Comma-separated directories to exclude

### secrets_rotate
Rotate a detected secret credential.

**Parameters:**
- `secret_type` (string, required) — One of: aws_access_key, aws_secret_key, github_token, stripe_key, gcp_key, azure_key
- `resource_id` (string, required) — ID of the key or resource

### secrets_audit_trail
Get the audit trail of secret rotations.

**Parameters:**
- `since` (string, optional) — ISO date filter
- `secret_type` (string, optional) — Filter by type

### secrets_update_vault
Update a Cortex vault entry.

**Parameters:**
- `key` (string, required) — Vault key
- `new_value` (string, required) — New secret value
- `old_value_hash` (string, optional) — SHA-256 of old value

### secrets_generate
Generate a cryptographically secure secret.

**Parameters:**
- `type` (string, default: "token") — password, api_key, token, rsa_key
- `length` (number, default: 32) — Secret length
- `options` (string, optional) — Additional JSON options

## Built-in Detection Patterns

15 patterns across 6 categories: AWS keys (AKIA/ASIA), GitHub tokens (ghp_/gho_/github_pat_), Stripe (sk_live_/rk_live_), GCP service accounts, Azure connections, generic API keys, private key blocks, JWT tokens, connection strings, basic auth headers.

## Configuration

UI settings:
- **Auto Rotate** (boolean, default: false) — Auto-rotate detected secrets
- **Rotation Interval Days** (number, default: 90)
- **Scan On Load** (boolean, default: false)

## Capabilities

- `tools` — Secret management tools
- `shell:run` — Execute rotation commands
- `fs:read` — Read files for scanning

## Development

```bash
deno task test
deno task validate
```

## License

MIT
