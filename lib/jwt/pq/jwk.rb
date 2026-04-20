# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

module JWT
  module PQ
    # JWK (JSON Web Key) import/export for ML-DSA keys.
    #
    # Follows the `draft-ietf-cose-dilithium` conventions for the `AKP`
    # ("Algorithm Key Pair") key type:
    #
    # - `kty`: `"AKP"`
    # - `alg`: `"ML-DSA-44"`, `"ML-DSA-65"`, or `"ML-DSA-87"`
    # - `pub`: base64url-encoded public key (no padding)
    # - `priv`: base64url-encoded private key (optional, no padding)
    # - `kid`: RFC 7638 thumbprint over the required members
    #
    # @example Export and re-import
    #   jwk = JWT::PQ::JWK.new(key).export
    #   restored = JWT::PQ::JWK.import(jwk)
    #
    # @see https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/ draft-ietf-cose-dilithium
    # @see https://www.rfc-editor.org/rfc/rfc7638 RFC 7638 (JWK Thumbprint)
    class JWK
      # Algorithm names accepted in the `alg` field.
      ALGORITHMS = MlDsa::ALGORITHMS.keys.freeze

      # Value of the `kty` field for all ML-DSA JWKs.
      KTY = "AKP"

      # @return [JWT::PQ::Key] the wrapped key.
      attr_reader :key

      # Wrap a {JWT::PQ::Key} for JWK operations.
      #
      # @param key [JWT::PQ::Key] the key to export or thumbprint.
      # @raise [KeyError] if `key` is not a {JWT::PQ::Key}.
      def initialize(key)
        raise KeyError, "Expected a JWT::PQ::Key, got #{key.class}" unless key.is_a?(JWT::PQ::Key)

        @key = key
      end

      # Export the key as a JWK hash.
      #
      # By default, only the public material is included. Pass
      # `include_private: true` to emit the `priv` field as well (and only
      # when the wrapped key actually has a private component).
      #
      # @param include_private [Boolean] include the `priv` field. Default: false.
      # @return [Hash{Symbol=>String}] a JWK with `:kty`, `:alg`, `:pub`,
      #   `:kid`, and optionally `:priv`.
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
      #
      # Accepts string or symbol keys. Validates `kty`, `alg`, and the
      # presence/base64url-ness of `pub` (and `priv` if present).
      #
      # @param jwk_hash [Hash] a JWK object.
      # @return [JWT::PQ::Key] a key reconstructed from the JWK — with a
      #   private component iff the JWK carried a `priv` field.
      # @raise [KeyError] on missing/wrong `kty`, missing/unsupported `alg`,
      #   missing `pub`, or invalid base64url in `pub`/`priv`.
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

      # Compute the JWK Thumbprint (RFC 7638) used as `kid`.
      #
      # Delegates to {JWT::PQ::Key#jwk_thumbprint}, which memoizes the
      # result on the key — repeated calls on the same key avoid
      # recomputing the canonical JSON + SHA-256 digest.
      #
      # @return [String] base64url-encoded SHA-256 thumbprint.
      def thumbprint
        @key.jwk_thumbprint
      end

      # Compute an RFC 7638 thumbprint from algorithm + public key bytes
      # without allocating a {JWK} or {JWT::PQ::Key} wrapper.
      #
      # @api private
      # @param algorithm [String] canonical algorithm name.
      # @param public_key [String] raw public key bytes.
      # @return [String] base64url-encoded SHA-256 thumbprint.
      def self.compute_thumbprint(algorithm, public_key)
        # RFC 7638 §3.2: canonical JSON over the required members in
        # lexicographic order (alg, kty, pub), no whitespace. Using
        # `JSON.generate` over an ordered Hash instead of string
        # interpolation so a future algorithm or key-byte change that
        # introduces a character needing JSON escape does not silently
        # produce a divergent thumbprint.
        pub_b64 = ::Base64.urlsafe_encode64(public_key, padding: false)
        canonical = JSON.generate({ alg: algorithm, kty: KTY, pub: pub_b64 })
        digest = OpenSSL::Digest::SHA256.digest(canonical)
        ::Base64.urlsafe_encode64(digest, padding: false)
      end

      # @api private
      def self.validate_kty!(jwk)
        kty = jwk["kty"]
        raise KeyError, "Missing 'kty' in JWK" unless kty
        raise KeyError, "Expected kty '#{KTY}', got '#{kty}'" unless kty == KTY
      end
      private_class_method :validate_kty!

      # @api private
      def self.validate_alg!(jwk)
        alg = jwk["alg"]
        raise KeyError, "Missing 'alg' in JWK" unless alg
        raise KeyError, "Unsupported algorithm '#{alg}'" unless ALGORITHMS.include?(alg)

        alg
      end
      private_class_method :validate_alg!

      # @api private
      def self.normalize_keys(hash)
        hash.transform_keys(&:to_s)
      end
      private_class_method :normalize_keys

      # @api private
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
