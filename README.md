# jwt-pq

[![Gem Version](https://badge.fury.io/rb/jwt-pq.svg)](https://rubygems.org/gems/jwt-pq)
[![CI](https://github.com/marcelopazzo/jwt-pq/actions/workflows/ci.yml/badge.svg)](https://github.com/marcelopazzo/jwt-pq/actions/workflows/ci.yml)
[![Cross-interop](https://github.com/marcelopazzo/jwt-pq/actions/workflows/interop.yml/badge.svg)](https://github.com/marcelopazzo/jwt-pq/actions/workflows/interop.yml)
[![codecov](https://codecov.io/gh/marcelopazzo/jwt-pq/graph/badge.svg)](https://codecov.io/gh/marcelopazzo/jwt-pq)

Post-quantum JWT signatures for Ruby. Adds **ML-DSA** (FIPS 204) support to the [ruby-jwt](https://github.com/jwt/ruby-jwt) ecosystem, with an optional **hybrid EdDSA + ML-DSA** mode.

## Features

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms
- Hybrid EdDSA + ML-DSA dual signatures
- Drop-in integration with `JWT.encode` / `JWT.decode`
- PEM serialization (SPKI / PKCS#8) via [pqc_asn1](https://github.com/msuliq/pqc_asn1)
- JWK export/import with RFC 7638 thumbprints

## Requirements

- Ruby >= 3.2
- CMake >= 3.15 and a C compiler — gcc or clang (for building the bundled liboqs)

## Installation

```ruby
# Gemfile
gem "jwt-pq"

# For hybrid EdDSA + ML-DSA mode (optional):
gem "jwt-eddsa"
```

liboqs is automatically compiled from source during gem installation (ML-DSA algorithms only, ~30 seconds).

### Using system liboqs

If you prefer to use a system-installed liboqs:

```bash
gem install jwt-pq -- --use-system-libraries
# or
JWT_PQ_USE_SYSTEM_LIBRARIES=1 gem install jwt-pq
# or in Bundler
bundle config build.jwt-pq --use-system-libraries
```

You can also point to a specific library with `OQS_LIB=/path/to/liboqs.dylib`.

## Usage

### Basic ML-DSA signing

```ruby
require "jwt/pq"

key = JWT::PQ::Key.generate(:ml_dsa_65)

# Encode
token = JWT.encode({ sub: "1234" }, key, "ML-DSA-65")

# Decode
decoded = JWT.decode(token, key, true, algorithms: ["ML-DSA-65"])
decoded.first # => { "sub" => "1234" }
```

### Verify with public key only

```ruby
pub_key = JWT::PQ::Key.from_public_key("ML-DSA-65", key.public_key)
JWT.decode(token, pub_key, true, algorithms: ["ML-DSA-65"])
```

### Hybrid EdDSA + ML-DSA

Requires `jwt-eddsa` gem.

```ruby
require "jwt/pq"

hybrid_key = JWT::PQ::HybridKey.generate(:ml_dsa_65)

token = JWT.encode({ sub: "1234" }, hybrid_key, "EdDSA+ML-DSA-65")

# Verify — both Ed25519 and ML-DSA signatures must be valid
decoded = JWT.decode(token, hybrid_key, true, algorithms: ["EdDSA+ML-DSA-65"])
```

The hybrid signature is a concatenation of `Ed25519 (64 bytes) || ML-DSA`, stored in the standard JWT signature field. The JWT header includes `"pq_alg": "ML-DSA-65"`.

### PEM serialization

```ruby
# Export
pub_pem  = key.to_pem          # SPKI format
priv_pem = key.private_to_pem  # PKCS#8 format

# Import
pub_key  = JWT::PQ::Key.from_pem(pub_pem)
full_key = JWT::PQ::Key.from_pem_pair(public_pem: pub_pem, private_pem: priv_pem)
```

### JWK

```ruby
jwk = JWT::PQ::JWK.new(key)

# Export
jwk.export
# => { kty: "AKP", alg: "ML-DSA-65", pub: "...", kid: "..." }

jwk.export(include_private: true)
# => { kty: "AKP", alg: "ML-DSA-65", pub: "...", priv: "...", kid: "..." }

# Import
restored = JWT::PQ::JWK.import(jwk_hash)
```

### JWK Set (JWKS)

For publishing multiple verification keys (e.g. during key rotation) or
consuming a remote JWKS endpoint:

```ruby
# Producer — publish verification keys on /.well-known/jwks.json
jwks = JWT::PQ::JWKSet.new([key_current, key_next])
File.write("jwks.json", jwks.to_json)

# Consumer — resolve the verification key by kid
jwks = JWT::PQ::JWKSet.import(JSON.parse(fetch_jwks))
_payload, header = JWT.decode(token, nil, false)        # unverified peek
key = jwks[header["kid"]] or raise "unknown kid"
payload, = JWT.decode(token, key, true, algorithms: [header["alg"]])
```

Members are indexed by their RFC 7638 thumbprint (the same value
`JWK#export` emits as `kid`). Remember to set the `kid` header when
signing: `JWT.encode(payload, key, alg, { kid: JWT::PQ::JWK.new(key).thumbprint })`.

## Algorithms

| Algorithm | NIST Level | Public Key | Signature | JWT `alg` value |
|-----------|-----------|------------|-----------|-----------------|
| ML-DSA-44 | 2 | 1,312 B | 2,420 B | `ML-DSA-44` |
| ML-DSA-65 | 3 | 1,952 B | 3,309 B | `ML-DSA-65` |
| ML-DSA-87 | 5 | 2,592 B | 4,627 B | `ML-DSA-87` |

**Note on token size:** ML-DSA signatures are significantly larger than classical algorithms. A JWT with ML-DSA-65 will have a ~4.4 KB signature (base64url encoded), compared to ~86 bytes for Ed25519 or ~342 bytes for RS256.

## Hybrid mode details

The hybrid algorithms (`EdDSA+ML-DSA-{44,65,87}`) provide defense-in-depth: if either algorithm is broken, the other still protects the token.

The `alg` header values follow a `ClassicAlg+PQAlg` convention. The IETF draft [`draft-ietf-cose-dilithium`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) is still evolving — these values may change in future versions to align with the final standard.

## Correctness

- **NIST ACVP known-answer tests.** `spec/jwt/pq/kat_spec.rb` runs the full sigVer KAT subset shipped with liboqs against `JWT::PQ::Key#verify` for ML-DSA-44/65/87, covering both positive and negative cases. These vectors are executed in CI on every push. (sigGen KATs are not used because FIPS 204 specifies hedged signing with internal randomness, which makes signature output non-deterministic.)
- **Cross-language interop.** The [`Cross-interop`](https://github.com/marcelopazzo/jwt-pq/actions/workflows/interop.yml) workflow signs with `jwt-pq` and verifies with [`dilithium-py`](https://pypi.org/project/dilithium-py/), and vice versa, for all three parameter sets. It runs on every push and weekly on `cron`.

## Performance

Measured with `bench/sign_throughput.rb` / `bench/verify_throughput.rb` (and the hybrid variants) using `benchmark-ips`. Hardware: Intel Core i9-9880H @ 2.30 GHz, macOS, Ruby 3.4.6, bundled liboqs 0.15.0, single-threaded.

| Algorithm | Sign | Verify |
|---|---|---|
| ML-DSA-44 | 8,026 ops/s (125 µs) | 11,074 ops/s (90 µs) |
| ML-DSA-65 | 5,972 ops/s (167 µs) | 9,339 ops/s (107 µs) |
| ML-DSA-87 | 4,911 ops/s (204 µs) | 6,471 ops/s (155 µs) |
| EdDSA+ML-DSA-65 | 4,695 ops/s (213 µs) | 3,924 ops/s (255 µs) |

Numbers are illustrative — rerun `bundle exec ruby bench/sign_throughput.rb` on your target hardware before capacity-planning. ML-DSA is ~1–2 orders of magnitude slower than Ed25519 (~70 k sigs/s on the same box); plan accordingly.

## Backends

ML-DSA operations are delegated to [liboqs](https://github.com/open-quantum-safe/liboqs), bundled and compiled during `gem install`. An alternative OpenSSL 3.5+ backend is tracked in [#14](https://github.com/marcelopazzo/jwt-pq/issues/14) and will be added once OpenSSL 3.5 ships widely in distros.

## Specification tracking

jwt-pq targets the current IETF specs for JOSE/COSE post-quantum signatures:

- [`draft-ietf-cose-dilithium`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) — ML-DSA in JOSE/COSE, including the `AKP` key type *(draft)*
- [RFC 9864](https://datatracker.ietf.org/doc/rfc9864/) — Fully-Specified Algorithms for JOSE and COSE *(published October 2025)*
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA itself *(final)*

Because `draft-ietf-cose-dilithium` is still pre-RFC, the JWK `kty`/`alg` values, header registration, and hybrid concatenation format may change between jwt-pq minor releases. Breaking changes will be called out in [CHANGELOG.md](CHANGELOG.md) and bump the minor version pre-1.0 (or the major version post-1.0).

## Thread safety

- `JWT::PQ::Key` and `JWT::PQ::HybridKey` are safe to share across threads for **verification**. The underlying `OQS_SIG` verify context is process-global and reused; verify itself is stateless at the liboqs level.
- **Signing** from multiple threads with the *same* `Key` instance is also safe in practice (liboqs ML-DSA sign does not mutate context state), but if you want the strongest guarantee, give each thread its own `Key` and use `destroy!` when done.
- `destroy!` mutates the receiver — do not call it concurrently with `#sign` / `#verify`.

## Algorithm registration

`require "jwt/pq"` registers `ML-DSA-{44,65,87}` and `EdDSA+ML-DSA-{44,65,87}` with ruby-jwt via the **public** `JWT::JWA::SigningAlgorithm.register_algorithm` API — this is not a monkey-patch. The registration is idempotent and coexists with other custom algorithms (e.g. `jwt-eddsa`). Load order between `jwt` and `jwt/pq` does not matter.

## Security

See [SECURITY.md](SECURITY.md) for the supported-versions policy, vulnerability reporting process, and how upstream liboqs advisories are handled.

## Development

```bash
bundle install          # compiles liboqs automatically
bundle exec rspec       # run tests
bundle exec rubocop     # lint
rake compile            # recompile liboqs manually
```

## License

[MIT](LICENSE)
