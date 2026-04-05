# frozen_string_literal: true

module JWT
  module PQ
    # Composite key combining an Ed25519 keypair with an ML-DSA keypair
    # for hybrid EdDSA + ML-DSA JWT signatures.
    class HybridKey
      attr_reader :ed25519_signing_key, :ed25519_verify_key, :ml_dsa_key

      # @param ed25519 [Ed25519::SigningKey, Ed25519::VerifyKey] Ed25519 key
      # @param ml_dsa [JWT::PQ::Key] ML-DSA key
      def initialize(ed25519:, ml_dsa:)
        require_eddsa_dependency!

        @ml_dsa_key = ml_dsa

        case ed25519
        when Ed25519::SigningKey
          @ed25519_signing_key = ed25519
          @ed25519_verify_key = ed25519.verify_key
        when Ed25519::VerifyKey
          @ed25519_signing_key = nil
          @ed25519_verify_key = ed25519
        else
          raise KeyError, "Expected Ed25519::SigningKey or Ed25519::VerifyKey, got #{ed25519.class}"
        end
      end

      # Generate a new hybrid keypair.
      def self.generate(ml_dsa_algorithm = :ml_dsa_65)
        require_eddsa_dependency!

        ed_key = Ed25519::SigningKey.generate
        ml_key = Key.generate(ml_dsa_algorithm)

        new(ed25519: ed_key, ml_dsa: ml_key)
      end

      # Whether both keys have private components (can sign).
      def private?
        !@ed25519_signing_key.nil? && @ml_dsa_key.private?
      end

      # The ML-DSA algorithm name (e.g., "ML-DSA-65").
      def algorithm
        @ml_dsa_key.algorithm
      end

      # The hybrid algorithm name (e.g., "EdDSA+ML-DSA-65").
      def hybrid_algorithm
        "EdDSA+#{@ml_dsa_key.algorithm}"
      end

      def self.require_eddsa_dependency!
        require "ed25519"
      rescue LoadError
        raise MissingDependencyError,
              "The 'jwt-eddsa' gem (or 'ed25519' gem) is required for hybrid " \
              "EdDSA+ML-DSA mode. Add it to your Gemfile: gem 'jwt-eddsa'"
      end
      private_class_method :require_eddsa_dependency!

      private

      def require_eddsa_dependency!
        self.class.send(:require_eddsa_dependency!)
      end
    end
  end
end
