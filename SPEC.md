# Specification tracking

This document records which external specifications each jwt-pq release
targets, what its current divergences are (if any), and the compatibility
policy for drafts in flight.

## Tracked specifications — jwt-pq 0.6.x

Last reviewed: **2026-04-22**.

| Spec                                                                                    | Role in jwt-pq                                                                                 | Status                      |
|-----------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|-----------------------------|
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)                                   | ML-DSA itself — key generation, signing, verification, key sizes                               | Final (August 2024)         |
| [RFC 9864](https://datatracker.ietf.org/doc/rfc9864/)                                   | Fully-Specified Algorithms for JOSE and COSE — underlies the `AKP` key type concept            | Final (October 2025)        |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) / [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) / [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) / [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWS wire format, JWK structure, `alg` registration, JWK thumbprints                            | Final                       |
| [`draft-ietf-cose-dilithium`](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) | `AKP` (`"Algorithm Key Pair"`) JWK key type and ML-DSA JWS `alg` names (`ML-DSA-44/65/87`)     | Internet-Draft, pre-RFC     |

The hybrid mode (`EdDSA+ML-DSA-*`) is jwt-pq's own convention —
concatenated `Ed25519 || ML-DSA` signatures with a `pq_alg` header for
cross-impl disambiguation. There is no IETF draft that specifies this
exact shape for EdDSA+ML-DSA; it is implemented here as an interop-safe
stepping stone until the JOSE WG publishes one.

## Known divergences from the specs

None at the time of writing. jwt-pq implements the ML-DSA JOSE convention
as currently written in the draft. Any divergence introduced in the
future (e.g. to work around an ambiguous draft point) will be listed
here with a link to the commit that introduced it.

## Compatibility policy

Because `draft-ietf-cose-dilithium` is an evolving Internet-Draft and
not yet an RFC, the `alg`, `kty`, and `pub`/`priv` field semantics can
change between draft revisions. Our policy for adapting to them:

1. **Pre-1.0 (current).** A breaking change in the draft that requires
   a wire-format change — renamed `kty`, renamed `alg`, field moved to
   a different section — ships in a new **minor** version (`0.4 → 0.5`).
   The CHANGELOG entry will call it out as breaking and name the draft
   revision motivating the change.

2. **Post-1.0.** The same class of breaking change ships in a new
   **major** version (`1.x → 2.x`). Minor versions may add support for
   a new draft revision side-by-side with the old one if doing so does
   not break wire-compatible deployments.

3. **Overlap window for in-flight drafts.** Where feasible we accept
   both the previous and the current draft's field names on the import
   side (`JWK.import`, `from_pem`) for one minor version following a
   change, and emit only the current draft's form on the export side.
   This gives operators a migration window without requiring a
   flag-day rollout.

4. **Final RFC.** When `draft-ietf-cose-dilithium` is published as an
   RFC, jwt-pq will bump to the RFC's final field names on the export
   side in a minor (pre-1.0) or major (post-1.0) release, and document
   the RFC reference here. The import side will continue accepting the
   last draft revision for at least one further minor to ease
   migration.

## Reporting divergences

If you find a place where jwt-pq's output does not match the spec,
please open an issue with:

- The jwt-pq version (`JWT::PQ::VERSION`)
- The spec section and line/field that disagrees
- A minimal example showing the difference (e.g. a JWK hash produced by
  jwt-pq alongside what the spec requires)

Correctness issues are prioritized over feature work.
