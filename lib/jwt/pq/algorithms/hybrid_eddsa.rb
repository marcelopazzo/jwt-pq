# frozen_string_literal: true

require "jwt"

module JWT
  module PQ
    module Algorithms
      # @api private
      #
      # JWT signing algorithm for hybrid EdDSA + ML-DSA signatures.
      #
      # The signature is a simple concatenation: ed25519_sig (64 bytes) || ml_dsa_sig.
      # This allows PQ-aware verifiers to validate both, while the fixed 64-byte
      # Ed25519 prefix makes it possible to split the signatures deterministically.
      #
      # Users interact with these algorithms via `JWT.encode`/`JWT.decode` by
      # name (`"EdDSA+ML-DSA-*"`); they never instantiate this class directly.
      class HybridEdDsa
        include ::JWT::JWA::SigningAlgorithm

        ED25519_SIG_SIZE = 64

        def initialize(alg)
          @alg = alg
          @ml_dsa_algorithm = alg.sub("EdDSA+", "")
          @header = { "alg" => alg, "pq_alg" => @ml_dsa_algorithm }.freeze
        end

        def header(*)
          @header
        end

        def sign(data:, signing_key:)
          unless signing_key.is_a?(JWT::PQ::HybridKey)
            raise_sign_error!(
              "Expected a JWT::PQ::HybridKey, got #{signing_key.class}. " \
              "Use JWT::PQ::HybridKey.generate to create a hybrid key."
            )
          end
          raise_sign_error!("Both Ed25519 and ML-DSA private keys required") unless signing_key.private?

          # Delegate to HybridKey#sign so the Ed25519 and ML-DSA halves
          # are taken atomically under the hybrid key's mutex — a
          # concurrent destroy! can no longer slip between the two
          # component signatures.
          signing_key.sign(data)
        end

        def verify(data:, signature:, verification_key:)
          unless verification_key.is_a?(JWT::PQ::HybridKey)
            raise_verify_error!(
              "Expected a JWT::PQ::HybridKey, got #{verification_key.class}."
            )
          end

          return false if signature.bytesize <= ED25519_SIG_SIZE

          ed_sig = signature.byteslice(0, ED25519_SIG_SIZE)
          ml_sig = signature.byteslice(ED25519_SIG_SIZE..)

          ed_valid = safe_ed25519_verify(verification_key.ed25519_verify_key, ed_sig, data)
          ml_valid = verification_key.ml_dsa_key.verify(data, ml_sig)

          # Bitwise `&`, not `&&`: both checks are already computed above,
          # and a bitwise AND over booleans has no short-circuit, so the
          # final combinator does not branch on which half failed. This
          # does not give a cryptographic constant-time guarantee (Ruby
          # can't), but it removes the obvious observable path.
          ed_valid & ml_valid
        # :nocov: — defensive rescue; Key#verify returns bool, does not raise PQ::Error in practice
        rescue JWT::PQ::Error
          false
          # :nocov:
        end

        # Boolean-returning wrapper over `Ed25519::VerifyKey#verify`, which
        # raises on failure. Gives the verify path a uniform shape for both
        # halves (both produce a bool by assignment, rather than one via
        # return value and one via rescue).
        #
        # @api private
        def safe_ed25519_verify(verify_key, signature, data)
          verify_key.verify(signature, data)
          true
        rescue Ed25519::VerifyError
          false
        end

        register_algorithm(new("EdDSA+ML-DSA-44"))
        register_algorithm(new("EdDSA+ML-DSA-65"))
        register_algorithm(new("EdDSA+ML-DSA-87"))
      end
    end
  end
end
