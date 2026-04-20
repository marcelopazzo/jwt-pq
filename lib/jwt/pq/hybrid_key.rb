# frozen_string_literal: true

module JWT
  module PQ
    # A composite key that pairs an Ed25519 keypair with an ML-DSA keypair
    # for hybrid `EdDSA+ML-DSA-*` JWT signatures.
    #
    # Hybrid mode concatenates the two signatures (`ed25519 || ml_dsa`) so
    # that a verifier only accepts the token if **both** signatures are
    # valid. The classical half remains secure against today's attackers
    # while the post-quantum half resists a future cryptographically
    # relevant quantum computer.
    #
    # Requires the `ed25519` gem (or `jwt-eddsa`, which depends on it).
    # Use {JWT::PQ.hybrid_available?} to probe availability.
    #
    # @example Generate a hybrid key and encode a JWT
    #   key = JWT::PQ::HybridKey.generate(:ml_dsa_65)
    #   token = JWT.encode({ sub: "u-1" }, key, "EdDSA+ML-DSA-65")
    #
    # @example Verification-only hybrid key
    #   verifier = JWT::PQ::HybridKey.new(
    #     ed25519: ed25519_verify_key,
    #     ml_dsa:  JWT::PQ::Key.from_public_key(:ml_dsa_65, pub_bytes)
    #   )
    class HybridKey
      # @return [Ed25519::SigningKey, nil] Ed25519 signing key, or nil for
      #   verification-only.
      attr_reader :ed25519_signing_key

      # @return [Ed25519::VerifyKey] Ed25519 verification key.
      attr_reader :ed25519_verify_key

      # @return [JWT::PQ::Key] ML-DSA keypair (public-only or full).
      attr_reader :ml_dsa_key

      # Build a hybrid key from existing Ed25519 and ML-DSA components.
      #
      # Pass an `Ed25519::SigningKey` for a full signing key, or an
      # `Ed25519::VerifyKey` for verification-only.
      #
      # @param ed25519 [Ed25519::SigningKey, Ed25519::VerifyKey] Ed25519 key.
      # @param ml_dsa [JWT::PQ::Key] ML-DSA keypair.
      # @raise [MissingDependencyError] if the `ed25519` gem is not installed.
      # @raise [KeyError] if `ed25519` is not one of the accepted key types.
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

      # Generate a fresh hybrid keypair.
      #
      # Creates both an Ed25519 `SigningKey` and an ML-DSA keypair of the
      # requested parameter set.
      #
      # @param ml_dsa_algorithm [Symbol, String] one of `:ml_dsa_44`,
      #   `:ml_dsa_65`, `:ml_dsa_87`. Defaults to `:ml_dsa_65`.
      # @return [HybridKey] a full hybrid keypair (signing + verification).
      # @raise [MissingDependencyError] if the `ed25519` gem is not installed.
      def self.generate(ml_dsa_algorithm = :ml_dsa_65)
        require_eddsa_dependency!

        ed_key = Ed25519::SigningKey.generate
        ml_key = Key.generate(ml_dsa_algorithm)

        new(ed25519: ed_key, ml_dsa: ml_key)
      end

      # @return [Boolean] true when both halves have private components and
      #   the key can be used for signing.
      def private?
        !@ed25519_signing_key.nil? && @ml_dsa_key.private?
      end

      # @return [String] the ML-DSA algorithm name (e.g. `"ML-DSA-65"`).
      def algorithm
        @ml_dsa_key.algorithm
      end

      # @return [String] the hybrid JWT algorithm name
      #   (e.g. `"EdDSA+ML-DSA-65"`).
      def hybrid_algorithm
        "EdDSA+#{@ml_dsa_key.algorithm}"
      end

      # Zero and discard private key material from both halves.
      #
      # After calling this, {#private?} becomes false and the key can only
      # be used for verification. Idempotent — safe on verification-only keys.
      #
      # @return [true]
      def destroy!
        @ml_dsa_key.destroy!
        if @ed25519_signing_key
          seed = @ed25519_signing_key.to_bytes
          seed.replace("\0" * seed.bytesize)
          @ed25519_signing_key = nil
        end
        true
      end

      # @return [String] short diagnostic string — never contains key material.
      def inspect
        "#<#{self.class} algorithm=#{hybrid_algorithm} private=#{private?}>"
      end
      alias to_s inspect

      # @api private
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
