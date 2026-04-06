# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-06

### Added

- Vendored liboqs build — `gem install jwt-pq` now compiles liboqs from source automatically
- `Key#destroy!` and `HybridKey#destroy!` for explicit zeroization of private key material
- `--use-system-libraries` escape hatch for users with pre-installed liboqs
- `JWT_PQ_LIBOQS_SOURCE` env var for air-gapped environments
- Path traversal protection in tarball extraction (defense-in-depth)
- Smoke test job in CI (builds gem, installs, runs end-to-end verification)
- Weekly CI schedule to catch dependency breakage
- Dependabot for automated dependency updates
- Secret scanning and push protection
- Code coverage with SimpleCov and Codecov

### Changed

- CMake and a C compiler (gcc/clang) are now required at install time
- `Key#inspect` and `HybridKey#inspect` no longer expose private key material
- `Key.resolve_algorithm` is now a private class method
- `JWK::ALGORITHMS` derived from `MlDsa::ALGORITHMS` (single source of truth)
- Pin CI actions to commit SHAs for security
- Use `Net::HTTP` instead of `URI.open` for tarball download
- Restrict CI workflow GITHUB_TOKEN permissions to `contents: read`

### Fixed

- ML-DSA verify with invalid key type now raises `DecodeError` instead of `EncodeError`
- JWK import now validates missing `pub` field and malformed base64url input
- FFI memory holding secret keys is now zeroed after use

### Dependencies

- Bump codecov/codecov-action from 5.5.4 to 6.0.0

## [0.1.0] - 2026-04-04

### Added

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature algorithms via liboqs FFI
- JWT signing/verification through `JWT.encode` / `JWT.decode` (ruby-jwt >= 3.0)
- `JWT::PQ::Key` for keypair generation and management
- PEM serialization (SPKI/PKCS#8) via pqc_asn1
- JWK export/import (kty: "AKP") with RFC 7638 thumbprints
- Hybrid EdDSA + ML-DSA mode (`EdDSA+ML-DSA-{44,65,87}`)
  - Concatenated signature format: Ed25519 (64B) || ML-DSA
  - Optional dependency on jwt-eddsa / ed25519
- Error classes: `LiboqsError`, `KeyError`, `SignatureError`, `MissingDependencyError`

[Unreleased]: https://github.com/marcelopazzo/jwt-pq/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/marcelopazzo/jwt-pq/releases/tag/v0.1.0
