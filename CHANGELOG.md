# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2026-02-18
### Changed
- Changed `Payload` format from binary concatenation to JSON object (Base64URL encoded).
- This restores readability of the internal structure while keeping the 3-part token format.

## [0.1.2] - 2026-02-18
### Changed
- Renamed `EncryptForDevice` to `Encrypt`.
- Renamed `DecryptForDevice` to `Decrypt`.

## [0.1.1] - 2026-02-18
### Changed
- Reverted method names to `EncryptForDevice` and `DecryptForDevice` (from `Seal`/`Open` in v0.1.0).

## [0.1.0] - 2026-02-18
### Changed
- **BREAKING**: Changed output format from JSON `Record` struct to compact string token `goseal.v1.<header>.<payload>`.
- **BREAKING**: Renamed `EncryptForDevice` to `Seal` (returns `string`).
- **BREAKING**: Renamed `DecryptForDevice` to `Open` (accepts `string`).
- Removed `Record` struct from public API.

## [0.0.1] - Initial Release

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
