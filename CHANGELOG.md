# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- ML-DSA verify with invalid key type now raises `DecodeError` instead of `EncodeError`

### Changed

- Pin CI actions to commit SHAs for security
- Add code coverage with SimpleCov and Codecov

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
