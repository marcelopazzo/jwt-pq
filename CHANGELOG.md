# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `JWT::PQ::JWKSet.import` (and `JWKSet.fetch`) now tolerates mixed JWKSes: members with unknown `kty` (e.g. RSA, EC, OKP) or unsupported `alg` within `kty: "AKP"` are silently skipped instead of aborting the whole set — enabling incremental PQ rollouts where a single `/.well-known/jwks.json` carries both classical and ML-DSA keys. Pass `strict: true` to restore the previous fail-fast behaviour. Recognized-but-malformed AKP members still raise `KeyError` (#34)

## [0.5.1] - 2026-04-22

### Changed

- Gemspec `homepage` now points to `https://jwt-pq.marcelopazzo.com` (the live verifier and docs site); `source_code_uri`, `changelog_uri`, and `bug_tracker_uri` remain on GitHub (#37)

## [0.5.0] - 2026-04-20

### Added

- `JWT::PQ::JWKSet` for RFC 7517 §5 JWK Sets — parse, serialize, lookup by `kid`, and enumerate keys (#22)
- Remote JWKS fetcher with TTL cache and ETag/If-None-Match revalidation for interop with identity providers (#24)
- YARD documentation across the public API surface (`@param`, `@return`, `@raise`, `@example`); `@api private` markers on internals (#21)
- `SPEC.md` tracking the IETF drafts jwt-pq targets (JOSE/COSE PQC) and the gem's compatibility policy (#28)
- Fuzz-style tests hardening `JWK` and `JWKSet` import against malformed input (#23)
- Ruby→Python JWK cross-interop CI job against an independent ML-DSA / FIPS 204 implementation (#19)
- Thumbprint test verifying `JWK#thumbprint` matches an independent RFC 7638 computation (#18)
- Weekly liboqs upstream release monitor workflow (#17)

### Fixed

- **Thread safety**: `Key#sign` / `#verify` / `#destroy!` now use a per-instance mutex instead of a class-level one, restoring real parallelism across keys while keeping a single key safe under concurrent use (#25)
- **Thread safety**: `MlDsa` handle-cache reads are now always synchronized — the previous double-checked pattern relied on Ruby memory-model guarantees that are not portable across implementations (#31)
- `JWK#thumbprint` now uses `JSON.generate` for the canonical member dictionary instead of string interpolation, eliminating a class of subtle escaping bugs (#27)
- `EdDSA+ML-DSA` hybrid `verify` no longer short-circuits between the two component verifications — both are always evaluated so neither timing nor error-path behavior leaks which half failed (#26)
- `HybridKey#destroy!` now wipes the underlying Ed25519 `@keypair` in addition to the ML-DSA half; FFI secret-key buffers are auto-zeroed on GC as a defense-in-depth finalizer (#32)
- `JWKSet` remote fetcher enforces the body cap during streaming read (not just post-hoc) and documents the URL-provenance contract callers must honor (#33)

### Changed

- `pqc_asn1` dependency tightened to `~> 0.1.0` (patch-only) so a future 0.2.0 with potential API breakage does not silently upgrade (#29)
- `bin/` directory no longer packaged into the published gem (smaller install footprint) (#29)

### Dependencies

- Bump `ruby/setup-ruby` from 1.301.0 to 1.302.0 (#30)

## [0.4.0] - 2026-04-19

### Added

- Hybrid-sign throughput benchmark at `bench/hybrid_sign_throughput.rb`
- Hybrid-verify throughput benchmark at `bench/hybrid_verify_throughput.rb`
- Parameterized `bench/sign_throughput.rb` and `bench/verify_throughput.rb` via `ALG` env var — previously hardcoded to `ML-DSA-65`, now supports all three security levels
- PEM key fixtures for ML-DSA-44 and ML-DSA-87 under `bench/fixtures/`
- `bench/generate_fixtures.rb` to regenerate bench fixtures idempotently
- Cross-implementation interop CI against `dilithium-py` (independent pure-Python ML-DSA / FIPS 204 implementation) — runs on push, PR, and weekly

### Changed

- **Hybrid EdDSA+ML-DSA-65 sign throughput: +12.1%** (5200 → 5831 sigs/s on Ruby 3.4.6 + liboqs 0.15.0). Inline type-check in `HybridEdDsa#sign` (+1.6%) plus cached frozen header hash and precomputed `ml_dsa_algorithm` at init (+10.4%) — `#header` is called once per `JWT.encode`, so eliminating the per-call Hash allocation and `String#sub` compounds noticeably.
- **Hybrid EdDSA+ML-DSA-65 verify throughput: +2.3%** (4812 → 4923 verifies/s). Inline type-check in `HybridEdDsa#verify`, mirroring the sign-side pattern.
- `bench/` directory no longer packaged into the published gem (smaller install footprint).

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

[Unreleased]: https://github.com/marcelopazzo/jwt-pq/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/marcelopazzo/jwt-pq/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/marcelopazzo/jwt-pq/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/marcelopazzo/jwt-pq/releases/tag/v0.1.0
