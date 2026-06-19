# Changelog

## [Unreleased]

### Changed

- Renamed manifest file from `cortex.json` to `manifest.json` for consistency with Cortex standard
- Standardized UI section structure to `ui.settings` format
- Normalized parameter naming: `defaultValue` → `default`, `options` → `enum`
- Added `homepage` field with repository URL
- Added `dependencies` field to manifest

### Fixed

- Replaced `console.log` with `ctx.logger.info()` in lifecycle hooks

## [1.0.1] — 2026-06-15

### Added

- Initial release

## [1.0.1] — 2026-06-17

### Added

- Initial project setup

## [1.0.0] — 2026-06-15

### Added

- Initial release of cortex-plugin-secret-rotation
- `secrets_scan` — Scan for 15 built-in secret patterns across 6 categories
- `secrets_rotate` — Rotate AWS, GitHub, Stripe, GCP, Azure secrets
- `secrets_audit_trail` — Query rotation audit history
- `secrets_update_vault` — Update Cortex vault entries
- `secrets_generate` — Generate passwords, API keys, tokens, RSA keys
