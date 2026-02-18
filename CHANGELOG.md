# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
