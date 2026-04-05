# frozen_string_literal: true

require "jwt"

module JWT
  module PQ
    module Algorithms
      # JWT signing algorithm for hybrid EdDSA + ML-DSA signatures.
      #
      # The signature is a simple concatenation: ed25519_sig (64 bytes) || ml_dsa_sig.
      # This allows PQ-aware verifiers to validate both, while the fixed 64-byte
      # Ed25519 prefix makes it possible to split the signatures deterministically.
      class HybridEdDsa
        include ::JWT::JWA::SigningAlgorithm

        ED25519_SIG_SIZE = 64

        def initialize(alg)
          @alg = alg
        end

        def header(*)
          { "alg" => alg, "pq_alg" => ml_dsa_algorithm }
        end

        def sign(data:, signing_key:)
          key = resolve_signing_key(signing_key)

          ed_sig = key.ed25519_signing_key.sign(data)
          ml_sig = key.ml_dsa_key.sign(data)

          # Concatenate: Ed25519 (64 bytes) || ML-DSA (variable)
          ed_sig + ml_sig
        end

        def verify(data:, signature:, verification_key:)
          key = resolve_verification_key(verification_key)

          return false if signature.bytesize <= ED25519_SIG_SIZE

          ed_sig = signature.byteslice(0, ED25519_SIG_SIZE)
          ml_sig = signature.byteslice(ED25519_SIG_SIZE..)

          ed_valid = begin
            key.ed25519_verify_key.verify(ed_sig, data)
            true
          rescue Ed25519::VerifyError
            false
          end

          ml_valid = key.ml_dsa_key.verify(data, ml_sig)

          ed_valid && ml_valid
        rescue JWT::PQ::Error
          false
        end

        private

        def ml_dsa_algorithm
          alg.sub("EdDSA+", "")
        end

        def resolve_signing_key(key)
          case key
          when JWT::PQ::HybridKey
            raise_sign_error!("Both Ed25519 and ML-DSA private keys required") unless key.private?
            key
          else
            raise_sign_error!(
              "Expected a JWT::PQ::HybridKey, got #{key.class}. " \
              "Use JWT::PQ::HybridKey.generate to create a hybrid key."
            )
          end
        end

        def resolve_verification_key(key)
          case key
          when JWT::PQ::HybridKey
            key
          else
            raise_verify_error!(
              "Expected a JWT::PQ::HybridKey, got #{key.class}."
            )
          end
        end

        register_algorithm(new("EdDSA+ML-DSA-44"))
        register_algorithm(new("EdDSA+ML-DSA-65"))
        register_algorithm(new("EdDSA+ML-DSA-87"))
      end
    end
  end
end
