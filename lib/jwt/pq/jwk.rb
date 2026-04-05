# frozen_string_literal: true

require "base64"
require "openssl"

module JWT
  module PQ
    # JWK (JSON Web Key) support for ML-DSA keys.
    #
    # Follows the draft-ietf-cose-dilithium conventions:
    #   kty: "AKP" (Algorithm Key Pair)
    #   alg: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
    #   pub: base64url-encoded public key
    #   priv: base64url-encoded private key (optional)
    class JWK
      ALGORITHMS = MlDsa::ALGORITHMS.keys.freeze
      KTY = "AKP"

      attr_reader :key

      def initialize(key)
        raise KeyError, "Expected a JWT::PQ::Key, got #{key.class}" unless key.is_a?(JWT::PQ::Key)

        @key = key
      end

      # Export the key as a JWK hash.
      def export(include_private: false)
        jwk = {
          kty: KTY,
          alg: @key.algorithm,
          pub: base64url_encode(@key.public_key),
          kid: thumbprint
        }

        jwk[:priv] = base64url_encode(@key.private_key) if include_private && @key.private?

        jwk
      end

      # Import a Key from a JWK hash.
      def self.import(jwk_hash)
        jwk = normalize_keys(jwk_hash)

        validate_kty!(jwk)
        alg = validate_alg!(jwk)
        raise KeyError, "Missing 'pub' in JWK" unless jwk.key?("pub")

        pub_bytes = decode_field(jwk, "pub")

        if jwk.key?("priv")
          priv_bytes = decode_field(jwk, "priv")
          Key.new(algorithm: alg, public_key: pub_bytes, private_key: priv_bytes)
        else
          Key.new(algorithm: alg, public_key: pub_bytes)
        end
      end

      # JWK Thumbprint (RFC 7638) for key identification.
      # Uses the required members: alg, kty, pub.
      def thumbprint
        canonical = "{\"alg\":\"#{@key.algorithm}\",\"kty\":\"#{KTY}\",\"pub\":\"#{base64url_encode(@key.public_key)}\"}"
        digest = OpenSSL::Digest::SHA256.digest(canonical)
        base64url_encode(digest)
      end

      def self.validate_kty!(jwk)
        kty = jwk["kty"]
        raise KeyError, "Missing 'kty' in JWK" unless kty
        raise KeyError, "Expected kty '#{KTY}', got '#{kty}'" unless kty == KTY
      end
      private_class_method :validate_kty!

      def self.validate_alg!(jwk)
        alg = jwk["alg"]
        raise KeyError, "Missing 'alg' in JWK" unless alg
        raise KeyError, "Unsupported algorithm '#{alg}'" unless ALGORITHMS.include?(alg)

        alg
      end
      private_class_method :validate_alg!

      def self.normalize_keys(hash)
        hash.transform_keys(&:to_s)
      end
      private_class_method :normalize_keys

      def self.decode_field(jwk, field)
        ::Base64.urlsafe_decode64(jwk[field])
      rescue ArgumentError => e
        raise KeyError, "Invalid base64url in JWK '#{field}': #{e.message}"
      end
      private_class_method :decode_field

      private

      def base64url_encode(bytes)
        ::Base64.urlsafe_encode64(bytes, padding: false)
      end
    end
  end
end
