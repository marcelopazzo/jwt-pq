# frozen_string_literal: true

require "jwt"

module JWT
  module PQ
    # @api private
    #
    # ruby-jwt `SigningAlgorithm` implementations that register jwt-pq's
    # algorithms on load. Not intended for direct use.
    module Algorithms
      # @api private
      #
      # JWT signing algorithm implementation for ML-DSA (FIPS 204).
      # Registers ML-DSA-44, ML-DSA-65, and ML-DSA-87 with the ruby-jwt library.
      # Users interact with these algorithms via `JWT.encode`/`JWT.decode` by
      # name; they never instantiate this class directly.
      class MlDsa
        include ::JWT::JWA::SigningAlgorithm

        def initialize(alg)
          @alg = alg
        end

        def sign(data:, signing_key:)
          key = resolve_signing_key(signing_key)
          key.sign(data)
        end

        def verify(data:, signature:, verification_key:)
          unless verification_key.is_a?(JWT::PQ::Key)
            raise_verify_error!(
              "Expected a JWT::PQ::Key, got #{verification_key.class}. " \
              "Use JWT::PQ::Key.generate(:#{alg_symbol}) to create a key."
            )
          end
          verification_key.verify(data, signature)
        # :nocov: — defensive rescue; Key#verify returns bool, does not raise PQ::Error in practice
        rescue JWT::PQ::Error
          false
          # :nocov:
        end

        private

        def resolve_signing_key(key)
          case key
          when JWT::PQ::Key
            raise_sign_error!("Private key required for signing") unless key.private?
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
