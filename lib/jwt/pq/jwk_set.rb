# frozen_string_literal: true

require "json"

module JWT
  module PQ
    # A set of JWKs (RFC 7517 §5) for publication and `kid`-based lookup.
    #
    # Typical producer flow — publish verification keys on
    # `/.well-known/jwks.json`:
    #
    # @example Publish a JWKS
    #   jwks = JWT::PQ::JWKSet.new([key_current, key_next])
    #   File.write("jwks.json", jwks.to_json)
    #
    # Typical consumer flow — pick the right key for an incoming JWT by the
    # `kid` header:
    #
    # @example Resolve a verification key by kid
    #   jwks = JWT::PQ::JWKSet.import(JSON.parse(fetch_jwks))
    #   _payload, header = JWT.decode(token, nil, false) # unverified peek
    #   key = jwks[header["kid"]] or raise "unknown kid"
    #   payload, = JWT.decode(token, key, true, algorithms: [header["alg"]])
    #
    # The set indexes members by their RFC 7638 JWK Thumbprint, which is the
    # `kid` {JWK#export} emits. If you import a JWKS that uses custom (non-
    # thumbprint) `kid` values, lookup by those custom values is not
    # supported — rely on thumbprints when generating the set.
    #
    # @see https://www.rfc-editor.org/rfc/rfc7517#section-5 RFC 7517 §5
    class JWKSet
      include Enumerable

      # Build a set from zero or more {JWT::PQ::Key}s.
      #
      # @param keys [Array<JWT::PQ::Key>, JWT::PQ::Key, nil] initial members.
      # @raise [KeyError] if any element is not a {JWT::PQ::Key}.
      def initialize(keys = [])
        @keys = []
        @kid_index = {}
        Array(keys).each { |k| add(k) }
      end

      # Add a key to the set.
      #
      # Idempotent: if a key with the same RFC 7638 thumbprint is already
      # in the set, the call is a no-op (Set semantics). The thumbprint
      # is computed before any mutation, so a failure to derive the
      # `kid` leaves the set unchanged.
      #
      # @param key [JWT::PQ::Key] the key to add.
      # @return [JWKSet] self, for chaining.
      # @raise [KeyError] if `key` is not a {JWT::PQ::Key}.
      def add(key)
        raise KeyError, "Expected a JWT::PQ::Key, got #{key.class}" unless key.is_a?(JWT::PQ::Key)

        kid = key.jwk_thumbprint
        return self if @kid_index.key?(kid)

        @keys << key
        @kid_index[kid] = key
        self
      end

      # Iterate over the keys in insertion order.
      #
      # @yieldparam key [JWT::PQ::Key]
      # @return [Enumerator] when called without a block.
      def each(&)
        @keys.each(&)
      end

      # @return [Integer] number of keys in the set.
      def size
        @keys.size
      end
      alias length size

      # @return [Boolean] true if the set is empty.
      def empty?
        @keys.empty?
      end

      # Look up a key by its RFC 7638 thumbprint (the `kid` from {JWK#export}).
      #
      # @param kid [String] the thumbprint to match.
      # @return [JWT::PQ::Key, nil] the matching key, or nil if not in the set.
      def find(kid)
        @kid_index[kid]
      end
      alias [] find

      # @return [Array<JWT::PQ::Key>] a frozen snapshot of the keys in the set.
      def keys
        @keys.dup.freeze
      end

      # Export the set as a JWKS hash.
      #
      # @param include_private [Boolean] include the `priv` field on each
      #   member that has a private component. Default: false.
      # @return [Hash{Symbol=>Array<Hash>}] a hash with a single `:keys`
      #   member, suitable for serialization with {#to_json}.
      def export(include_private: false)
        { keys: @keys.map { |k| JWK.new(k).export(include_private: include_private) } }
      end

      # Serialize the set as a JWKS JSON document.
      #
      # Always emits public-only keys — the `priv` field is never
      # written out. This keeps the method safe for arbitrary nesting
      # inside other JSON (e.g. `{ jwks: set }.to_json`), where Ruby's
      # stdlib JSON passes a generator state as a positional argument.
      # To publish private material (unusual), call
      # `JSON.generate(set.export(include_private: true))` explicitly.
      #
      # @return [String] a JSON document ready for `/.well-known/jwks.json`.
      def to_json(*)
        export.to_json(*)
      end

      # @return [String] short diagnostic string — never contains key material.
      def inspect
        "#<#{self.class} size=#{size}>"
      end
      alias to_s inspect

      # Import a JWKS from a Hash or JSON string.
      #
      # Each member is reconstructed via {JWT::PQ::JWK.import}; malformed
      # members raise {KeyError}.
      #
      # ML-DSA public keys are ~1.3–2.6 KB each, so a JWKS with N keys is
      # at least N × ~2 KB. When ingesting untrusted JWKS payloads (e.g.
      # a remote `/.well-known/jwks.json`), bound the HTTP body size
      # before calling `import` — this method does not cap the number of
      # members.
      #
      # @param source [Hash, String] a JWKS hash or JSON string with a
      #   `"keys"` array.
      # @return [JWKSet] a new set with all parsed members.
      # @raise [KeyError] if `source` is not a Hash/String, if the `keys`
      #   field is missing or not an Array, or if any member fails to import.
      def self.import(source)
        hash = coerce_to_hash(source)
        raise KeyError, "Expected Hash for JWKS body, got #{hash.class}" unless hash.is_a?(Hash)

        hash = hash.transform_keys(&:to_s)
        raise KeyError, "Missing 'keys' in JWKS" unless hash.key?("keys")
        raise KeyError, "'keys' must be an Array" unless hash["keys"].is_a?(Array)

        members = hash["keys"].map { |jwk| JWT::PQ::JWK.import(jwk) }
        new(members)
      end

      # @api private
      def self.coerce_to_hash(source)
        case source
        when String
          begin
            ::JSON.parse(source)
          rescue ::JSON::ParserError => e
            raise KeyError, "Invalid JSON for JWKS: #{e.message}"
          end
        when Hash then source
        else raise KeyError, "Expected Hash or JSON String for JWKS, got #{source.class}"
        end
      end
      private_class_method :coerce_to_hash
    end
  end
end
