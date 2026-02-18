# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-02-18
### Changed
- Renamed `EncryptForDevice` to `Encrypt`.
- Renamed `DecryptForDevice` to `Decrypt`.
- Reverted to original `Record` struct and JSON format (v0.1.4 was a full revert).

## [0.1.4] - 2026-02-18
### Changed
- **CRITICAL REVERT**: Reverted all changes from v0.1.0, v0.1.1, v0.1.2, v0.1.3.
- Codebase is now identical to pre-v0.1.0 state.

## [0.1.3] - 2026-02-18

### Added
- Split package into multiple files by responsibility.
- Added typed/sentinel errors for key and record failures.
- Added unit tests, fuzz test, and executable example.
- Added CI workflow with test, vet, race, and fuzz smoke checks.
- Added README with usage and security notes.

### Changed
- Fixed KEK derivation symmetry between encrypt/decrypt flows.
- Propagated random source errors instead of ignoring them.
- Set module path to `github.com/acolev/goseal`.
