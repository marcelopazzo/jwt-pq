# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Parameterized bench harnesses (`bench/sign_throughput.rb`, `bench/verify_throughput.rb`) via `ALG` env var — previously hardcoded to `ML-DSA-65`, now supports all three security levels
- PEM key fixtures for ML-DSA-44 and ML-DSA-87 under `bench/fixtures/`
- `bench/generate_fixtures.rb` to (re)generate fixture keys idempotently

### Benchmarks

Throughput on Ruby 3.4.6, macOS x86_64, liboqs 0.15.0 (benchmark-ips, 2s warmup + 5s measurement):

| Algorithm  |      Sign |     Verify |
|------------|----------:|-----------:|
| ML-DSA-44  |  9678 ops/s  | 12650 ops/s |
| ML-DSA-65  |  6236 ops/s  |  8567 ops/s |
| ML-DSA-87  |  3591 ops/s  |  6510 ops/s |

## [0.3.0] - 2026-04-19

### Added

- Sign-throughput benchmark at `bench/sign_throughput.rb` with a fixed PEM key fixture (`bench/fixtures/ml_dsa_65_sk.pem`), driven by `benchmark-ips`
- Verify-throughput benchmark at `bench/verify_throughput.rb`
- NIST ACVP sigVer KAT tests at `spec/jwt/pq/kat_spec.rb` — external interface, pure ML-DSA, empty context; covers ML-DSA-44, ML-DSA-65, and ML-DSA-87 with both passing and known-bad signatures as a canonical correctness gate
- `JWT::PQ::MlDsa#sign_with_sk_buffer` and `#verify_with_pk_buffer` — fast paths that accept pre-populated FFI buffers. The existing bytes-in `#sign` / `#verify` APIs are unchanged

### Changed

- **ML-DSA signing throughput: +2.6%** (from 6676 to 6849 sigs/s on Ruby 3.4.6 + liboqs 0.15.0 for ML-DSA-65). Class-level cache of the `OQS_SIG` handle per algorithm avoids `OQS_SIG_new`/`OQS_SIG_free` per call; per-`Key` memoization of the secret-key FFI buffer avoids a 4032-byte allocation + copy per sign
- **ML-DSA verification throughput: +19.4%** (from 7995 to 9548 verifies/s on the same setup for ML-DSA-65). Class-level cache of the `OQS_SIG` handle for verify; per-`Key` memoization of the public-key FFI buffer; inlined type-check in the JWA verify entry point. `Key#verify` now reaches 93% of the raw `OQS_SIG_verify` ceiling; remaining overhead lives inside `ruby-jwt`
- `Key#destroy!` now also zeroes the cached secret-key FFI buffer (`@sk_buffer`) in addition to `@private_key`, preserving the secure-erase contract after the buffer memoization

### Dependencies

- Add `benchmark-ips ~> 2.14` as a development/test dependency (powers the bench harnesses)
- Bump `ruby/setup-ruby` from 1.299.0 to 1.301.0 (#2)

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

[Unreleased]: https://github.com/marcelopazzo/jwt-pq/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/marcelopazzo/jwt-pq/releases/tag/v0.1.0
