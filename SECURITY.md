# Security Policy

## Supported versions

jwt-pq is pre-1.0. Only the latest minor release receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Report privately via GitHub's [private vulnerability reporting](https://github.com/marcelopazzo/jwt-pq/security/advisories/new) or by email to `security@marcelopazzo.com`.

Include:

- Affected version(s)
- Reproduction steps or proof of concept
- Impact assessment (key recovery, signature forgery, denial of service, etc.)

You should receive an acknowledgement within **72 hours**. A fix or mitigation plan will follow within **14 days** for high-severity issues.

## Scope

In scope:

- Signature forgery, key recovery, or authentication bypass in `JWT::PQ::Key`, `JWT::PQ::HybridKey`, or the JWT algorithm adapters
- JWK/PEM parsers accepting malformed input in a way that leaks private key material or enables forgery
- Memory safety issues in the FFI layer (e.g. out-of-bounds reads through user-controlled inputs)

Out of scope (report upstream):

- Vulnerabilities in [liboqs](https://github.com/open-quantum-safe/liboqs) itself — report to the liboqs maintainers
- Vulnerabilities in [ruby-jwt](https://github.com/jwt/ruby-jwt), [ed25519](https://github.com/RubyCrypto/ed25519), or [pqc_asn1](https://github.com/msuliq/pqc_asn1) — report to those projects

## Upstream liboqs advisories

jwt-pq bundles a pinned version of liboqs (see `LIBOQS_VERSION` in `ext/jwt/pq/extconf.rb`, currently **0.15.0**, integrity-checked against a SHA-256 of the source tarball).

When [liboqs](https://github.com/open-quantum-safe/liboqs/security/advisories) publishes a security advisory affecting an algorithm we ship:

1. A patch release of jwt-pq will bump `LIBOQS_VERSION` to the fixed upstream version.
2. The release will be cut within **7 days** of the liboqs advisory for high-severity issues, **30 days** for medium/low.
3. The changelog entry and GitHub Release notes will link to the upstream advisory.

Users running with `--use-system-libraries` are responsible for upgrading the system liboqs themselves.

## Cryptographic notes

- ML-DSA operations (keygen, sign, verify) are delegated to liboqs in C. jwt-pq does not reimplement the algorithm.
- Private key material is wiped via `#destroy!` on `JWT::PQ::Key` / `JWT::PQ::HybridKey`, and during PEM import via `PqcAsn1::SecureBuffer`.
- jwt-pq does not perform manual constant-time comparisons on signatures or MACs — signature verification returns a boolean from liboqs, and there are no equality checks on key/signature bytes in the Ruby layer.
- Randomness for keygen and signing is sourced from liboqs' internal RNG (which uses the system CSPRNG).
