# frozen_string_literal: true

module JWT
  module PQ
    # Represents an ML-DSA keypair (public + optional private key).
    # Used as the signing/verification key for JWT operations.
    class Key
      ALGORITHM_ALIASES = {
        ml_dsa_44: "ML-DSA-44",
        ml_dsa_65: "ML-DSA-65",
        ml_dsa_87: "ML-DSA-87"
      }.freeze

      attr_reader :algorithm, :public_key, :private_key

      def initialize(algorithm:, public_key:, private_key: nil)
        @algorithm = resolve_algorithm(algorithm)
        @ml_dsa = MlDsa.new(@algorithm)
        @public_key = public_key
        @private_key = private_key

        validate!
      end

      # Generate a new keypair for the given algorithm.
      def self.generate(algorithm)
        alg_name = resolve_algorithm(algorithm)
        ml_dsa = MlDsa.new(alg_name)
        pk, sk = ml_dsa.keypair

        new(algorithm: alg_name, public_key: pk, private_key: sk)
      end

      # Create a Key from raw public key bytes (verification only).
      def self.from_public_key(algorithm, public_key_bytes)
        new(algorithm: algorithm, public_key: public_key_bytes)
      end

      # Sign data using the private key.
      def sign(data)
        raise KeyError, "Private key not available — cannot sign" unless @private_key

        @ml_dsa.sign(data, @private_key)
      end

      # Verify a signature using the public key.
      def verify(data, signature)
        @ml_dsa.verify(data, signature, @public_key)
      end

      # Whether this key can be used for signing.
      def private?
        !@private_key.nil?
      end

      def self.resolve_algorithm(algorithm)
        ALGORITHM_ALIASES.fetch(algorithm.to_sym) { algorithm.to_s }
      end

      private

      def resolve_algorithm(algorithm)
        self.class.resolve_algorithm(algorithm)
      end

      def validate!
        expected_pk = @ml_dsa.public_key_size
        if @public_key.bytesize != expected_pk
          raise KeyError,
                "Invalid public key size for #{@algorithm}: " \
                "expected #{expected_pk}, got #{@public_key.bytesize}"
        end

        return unless @private_key

        expected_sk = @ml_dsa.secret_key_size
        return if @private_key.bytesize == expected_sk

        raise KeyError,
              "Invalid private key size for #{@algorithm}: " \
              "expected #{expected_sk}, got #{@private_key.bytesize}"
      end
    end
  end
end
