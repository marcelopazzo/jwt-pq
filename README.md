# jwt-pq

Post-quantum JWT signatures for Ruby. Adds **ML-DSA** (FIPS 204) support to the [ruby-jwt](https://github.com/jwt/ruby-jwt) ecosystem, with an optional **hybrid EdDSA + ML-DSA** mode.

## Features

- ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms
- Hybrid EdDSA + ML-DSA dual signatures
- Drop-in integration with `JWT.encode` / `JWT.decode`
- PEM serialization (SPKI / PKCS#8) via [pqc_asn1](https://github.com/msuliq/pqc_asn1)
- JWK export/import with RFC 7638 thumbprints

## Requirements

- Ruby >= 3.2
- [liboqs](https://github.com/open-quantum-safe/liboqs) (shared library)

### Installing liboqs

```bash
# macOS
brew install cmake ninja
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install

# Ubuntu / Debian
sudo apt-get install cmake ninja-build
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
```

You can also set the `OQS_LIB` environment variable to point to a custom `liboqs.so` / `liboqs.dylib` path.

## Installation

```ruby
# Gemfile
gem "jwt-pq"

# For hybrid EdDSA + ML-DSA mode (optional):
gem "jwt-eddsa"
```

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

## Algorithms

| Algorithm | NIST Level | Public Key | Signature | JWT `alg` value |
|-----------|-----------|------------|-----------|-----------------|
| ML-DSA-44 | 2 | 1,312 B | 2,420 B | `ML-DSA-44` |
| ML-DSA-65 | 3 | 1,952 B | 3,309 B | `ML-DSA-65` |
| ML-DSA-87 | 5 | 2,592 B | 4,627 B | `ML-DSA-87` |

**Note on token size:** ML-DSA signatures are significantly larger than classical algorithms. A JWT with ML-DSA-65 will have a ~4.4 KB signature (base64url encoded), compared to ~86 bytes for Ed25519 or ~342 bytes for RS256.

## Hybrid mode details

The hybrid algorithms (`EdDSA+ML-DSA-{44,65,87}`) provide defense-in-depth: if either algorithm is broken, the other still protects the token.

The `alg` header values follow a `ClassicAlg+PQAlg` convention. The IETF draft `draft-ietf-cose-dilithium` is still evolving — these values may change in future versions to align with the final standard.

## Development

```bash
bundle install
OQS_LIB=/path/to/liboqs.dylib bundle exec rspec
bundle exec rubocop
```

## License

[MIT](LICENSE)
