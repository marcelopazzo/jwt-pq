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

          ed_sig = signing_key.ed25519_signing_key.sign(data)
          ml_sig = signing_key.ml_dsa_key.sign(data)

          # Concatenate: Ed25519 (64 bytes) || ML-DSA (variable)
          ed_sig + ml_sig
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

          ed_valid = begin
            verification_key.ed25519_verify_key.verify(ed_sig, data)
            true
          rescue Ed25519::VerifyError
            false
          end

          ml_valid = verification_key.ml_dsa_key.verify(data, ml_sig)

          ed_valid && ml_valid
        # :nocov: — defensive rescue; Key#verify returns bool, does not raise PQ::Error in practice
        rescue JWT::PQ::Error
          false
          # :nocov:
        end

        register_algorithm(new("EdDSA+ML-DSA-44"))
        register_algorithm(new("EdDSA+ML-DSA-65"))
        register_algorithm(new("EdDSA+ML-DSA-87"))
      end
    end
  end
end
