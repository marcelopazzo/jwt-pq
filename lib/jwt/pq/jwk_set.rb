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
      # By default, members this gem cannot represent — unknown `kty`
      # (e.g. `RSA`, `EC`, `OKP`) or unknown `alg` within `kty: "AKP"`
      # (e.g. a future ML-DSA parameter set or a sibling PQ algorithm not
      # yet implemented here) — are silently dropped. This keeps the set
      # usable during an incremental PQ rollout, where a single
      # `/.well-known/jwks.json` carries both classical and ML-DSA keys.
      #
      # Members that **are** in scope (`kty: "AKP"` with a supported
      # `alg`) but malformed — missing `pub`, wrong field type, invalid
      # base64url, wrong key size — still raise {KeyError}: that is a
      # real bug in the emitter, not an interop boundary.
      #
      # Pass `strict: true` to restore the previous fail-fast behaviour,
      # where any unknown `kty`/`alg` raises.
      #
      # ML-DSA public keys are ~1.3–2.6 KB each, so a JWKS with N keys is
      # at least N × ~2 KB. When ingesting untrusted JWKS payloads (e.g.
      # a remote `/.well-known/jwks.json`), bound the HTTP body size
      # before calling `import` — this method does not cap the number of
      # members.
      #
      # @param source [Hash, String] a JWKS hash or JSON string with a
      #   `"keys"` array.
      # @param strict [Boolean] if true, unknown `kty`/`alg` members
      #   raise {KeyError} instead of being skipped. Default: false.
      # @return [JWKSet] a new set with the parsed in-scope members.
      # @raise [KeyError] if `source` is not a Hash/String, if the `keys`
      #   field is missing or not an Array, if an in-scope member is
      #   malformed, or (only when `strict: true`) if any member has an
      #   unknown `kty`/`alg`.
      def self.import(source, strict: false)
        hash = coerce_to_hash(source)
        raise KeyError, "Expected Hash for JWKS body, got #{hash.class}" unless hash.is_a?(Hash)

        hash = hash.transform_keys(&:to_s)
        raise KeyError, "Missing 'keys' in JWKS" unless hash.key?("keys")
        raise KeyError, "'keys' must be an Array" unless hash["keys"].is_a?(Array)

        members = hash["keys"].filter_map { |jwk| import_member(jwk, strict: strict) }
        new(members)
      end

      # @api private
      def self.import_member(jwk, strict:)
        return nil unless strict || JWT::PQ::JWK.recognized?(jwk)

        JWT::PQ::JWK.import(jwk)
      end
      private_class_method :import_member

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

      # Fetch a JWKS from a URL, honouring the process-global cache.
      #
      # Convenience wrapper around {Loader#fetch} using
      # {Loader.default} — the cache is shared across all callers, so
      # repeated hits on the same URL within `cache_ttl` seconds return
      # the in-memory set without touching the network.
      #
      # See {Loader} for the full option reference (cache TTL, timeouts,
      # body-size cap, HTTPS enforcement, ETag-based revalidation).
      #
      # @example Verify a token using a remote JWKS
      #   jwks = JWT::PQ::JWKSet.fetch("https://issuer.example/.well-known/jwks.json")
      #   _payload, header = JWT.decode(token, nil, false)
      #   key = jwks[header["kid"]] or raise "unknown kid"
      #   payload, = JWT.decode(token, key, true, algorithms: [header["alg"]])
      #
      # By default, members with unknown `kty`/`alg` in the fetched
      # body are skipped (see {.import}); pass `strict: true` to make
      # them raise.
      #
      # @param url [String] absolute JWKS URL.
      # @return [JWKSet] the parsed set of verification keys.
      # @raise [JWKSFetchError] on fetch failure (see {Loader#fetch}).
      # @raise [KeyError] if the fetched body is not a valid JWKS.
      def self.fetch(url, **)
        Loader.default.fetch(url, **)
      end
    end
  end
end
