# frozen_string_literal: true

require "jwt"

module JWT
  module PQ
    module Algorithms
      # JWT signing algorithm implementation for ML-DSA (FIPS 204).
      # Registers ML-DSA-44, ML-DSA-65, and ML-DSA-87 with the ruby-jwt library.
      class MlDsa
        include ::JWT::JWA::SigningAlgorithm

        def initialize(alg)
          @alg = alg
        end

        def sign(data:, signing_key:)
          key = resolve_key(signing_key)
          raise_sign_error!("Private key required for signing") unless key.private?
          key.sign(data)
        end

        def verify(data:, signature:, verification_key:)
          key = resolve_key(verification_key)
          key.verify(data, signature)
        rescue JWT::PQ::Error
          false
        end

        private

        def resolve_key(key)
          case key
          when JWT::PQ::Key
            key
          else
            raise_sign_error!(
              "Expected a JWT::PQ::Key, got #{key.class}. " \
              "Use JWT::PQ::Key.generate(:#{alg_symbol}) to create a key."
            )
          end
        end

        def alg_symbol
          alg.downcase.tr("-", "_")
        end

        register_algorithm(new("ML-DSA-44"))
        register_algorithm(new("ML-DSA-65"))
        register_algorithm(new("ML-DSA-87"))
      end
    end
  end
end
