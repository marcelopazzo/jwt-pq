# frozen_string_literal: true

require "pqc_asn1"

module JWT
  module PQ
    # An ML-DSA keypair (public key + optional private key) used for JWT
    # signing and verification.
    #
    # Prefer the class-level constructors over {.new}:
    #
    # - {.generate} — create a fresh keypair
    # - {.from_pem} — import from a combined SPKI or PKCS#8 PEM
    # - {.from_pem_pair} — import from separate public/private PEMs
    # - {.from_public_key} — wrap raw public key bytes (verification only)
    #
    # @example Generate and sign
    #   key = JWT::PQ::Key.generate(:ml_dsa_65)
    #   token = JWT.encode({ sub: "u-1" }, key, "ML-DSA-65")
    #
    # @example Verification-only key
    #   verifier = JWT::PQ::Key.from_public_key(:ml_dsa_65, pub_bytes)
    #   JWT.decode(token, verifier, true, algorithms: ["ML-DSA-65"])
    class Key # rubocop:disable Metrics/ClassLength
      # Symbol → canonical algorithm name.
      ALGORITHM_ALIASES = {
        ml_dsa_44: "ML-DSA-44",
        ml_dsa_65: "ML-DSA-65",
        ml_dsa_87: "ML-DSA-87"
      }.freeze

      # Algorithm name → ASN.1 OID.
      ALGORITHM_OIDS = {
        "ML-DSA-44" => PqcAsn1::OID::ML_DSA_44,
        "ML-DSA-65" => PqcAsn1::OID::ML_DSA_65,
        "ML-DSA-87" => PqcAsn1::OID::ML_DSA_87
      }.freeze

      # ASN.1 OID → algorithm name.
      OID_TO_ALGORITHM = ALGORITHM_OIDS.invert.freeze

      # @return [String] canonical algorithm name (`"ML-DSA-44"`, `"ML-DSA-65"`, or `"ML-DSA-87"`).
      attr_reader :algorithm

      # @return [String] raw public key bytes.
      attr_reader :public_key

      # @return [String, nil] raw private (secret) key bytes, or nil for
      #   verification-only keys.
      attr_reader :private_key

      # Low-level constructor. Prefer {.generate}, {.from_pem}, {.from_pem_pair},
      # or {.from_public_key} in application code.
      #
      # @param algorithm [Symbol, String] one of `:ml_dsa_44`, `:ml_dsa_65`,
      #   `:ml_dsa_87` (or the canonical string form).
      # @param public_key [String] raw public key bytes of the correct size
      #   for the algorithm.
      # @param private_key [String, nil] raw private key bytes, or nil for a
      #   verification-only key.
      # @raise [UnsupportedAlgorithmError] if `algorithm` is not recognized.
      # @raise [KeyError] if a key's byte size does not match the algorithm.
      def initialize(algorithm:, public_key:, private_key: nil)
        @algorithm = resolve_algorithm(algorithm)
        @ml_dsa = MlDsa.new(@algorithm)
        @public_key = public_key
        @private_key = private_key

        validate!
      end

      # Generate a new keypair for the given algorithm.
      #
      # @param algorithm [Symbol, String] one of `:ml_dsa_44`, `:ml_dsa_65`,
      #   `:ml_dsa_87` (or the canonical string form).
      # @return [Key] a new keypair with both public and private components.
      # @raise [UnsupportedAlgorithmError] if `algorithm` is not recognized.
      def self.generate(algorithm)
        alg_name = resolve_algorithm(algorithm)
        ml_dsa = MlDsa.new(alg_name)
        pk, sk = ml_dsa.keypair

        new(algorithm: alg_name, public_key: pk, private_key: sk)
      end

      # Wrap raw public key bytes for verification-only use.
      #
      # @param algorithm [Symbol, String] the algorithm the public key belongs to.
      # @param public_key_bytes [String] raw public key bytes.
      # @return [Key] a verification-only key ({#private?} returns false).
      def self.from_public_key(algorithm, public_key_bytes)
        new(algorithm: algorithm, public_key: public_key_bytes)
      end

      # Sign data using the private key.
      #
      # @param data [String] message bytes to sign.
      # @return [String] raw signature bytes.
      # @raise [KeyError] if this key has no private component.
      # @raise [SignatureError] if liboqs reports a signing failure.
      def sign(data)
        raise KeyError, "Private key not available — cannot sign" unless @private_key

        @ml_dsa.sign_with_sk_buffer(data, sk_buffer)
      end

      # Verify a signature against data using the public key.
      #
      # @param data [String] message bytes that were signed.
      # @param signature [String] raw signature bytes produced by {#sign}.
      # @return [Boolean] true if the signature is valid, false otherwise.
      def verify(data, signature)
        @ml_dsa.verify_with_pk_buffer(data, signature, pk_buffer)
      end

      # @return [Boolean] true when this key has a private component and can sign.
      def private?
        !@private_key.nil?
      end

      # Zero and discard private key material from Ruby memory.
      #
      # After calling this, {#private?} becomes false and the key can only
      # be used for verification. Idempotent — safe to call multiple times,
      # and on verification-only keys.
      #
      # @return [true]
      def destroy!
        if @private_key
          @private_key.replace("\0" * @private_key.bytesize)
          @private_key = nil
        end
        @sk_buffer&.clear
        @sk_buffer = nil
        true
      end

      # @return [String] short diagnostic string — never contains key material.
      def inspect
        "#<#{self.class} algorithm=#{@algorithm} private=#{private?}>"
      end
      alias to_s inspect

      # RFC 7638 JWK Thumbprint for this key, memoized.
      #
      # The thumbprint depends only on the canonical JSON of
      # `{alg, kty, pub}` — all immutable for the lifetime of a Key —
      # so it is computed lazily on first access and cached. Useful for
      # callers (e.g. {JWT::PQ::JWKSet}) that index many keys by `kid`
      # without wanting to allocate a {JWK} wrapper each time.
      #
      # Safe to call concurrently on a shared key: the inputs are
      # immutable post-construction, so a concurrent first access at
      # worst recomputes the same deterministic string; the `||=`
      # assignment is a single atomic reference write on MRI.
      #
      # @return [String] base64url-encoded SHA-256 thumbprint.
      def jwk_thumbprint
        @jwk_thumbprint ||= JWT::PQ::JWK.compute_thumbprint(@algorithm, @public_key)
      end

      # Import a Key from a PEM string.
      #
      # Accepts both SPKI (public-only) and PKCS#8 (private + embedded public)
      # PEM documents. For a PKCS#8 PEM that does not carry the public key,
      # use {.from_pem_pair} with a separate public PEM instead.
      #
      # @param pem_string [String] a PEM-encoded key document.
      # @return [Key] a public-only or full keypair, depending on the PEM format.
      # @raise [KeyError] for unknown OIDs or PKCS#8 PEMs missing the public key.
      def self.from_pem(pem_string)
        info = PqcAsn1::DER.parse_pem(pem_string)
        alg_name = resolve_oid!(info.oid)

        case info.format
        when :spki  then new(algorithm: alg_name, public_key: info.key)
        when :pkcs8 then build_from_pkcs8(info, alg_name)
        # :nocov: — defensive guard; PqcAsn1::DER.parse_pem only returns :spki or :pkcs8
        else raise KeyError, "Unsupported PEM format: #{info.format}"
          # :nocov:
        end
      ensure
        info&.key&.wipe! if info&.format == :pkcs8
      end

      # Import a Key from separate public and private PEM strings.
      #
      # Use this when your private PEM is PKCS#8 without an embedded public
      # key, or when public and private material come from different sources.
      #
      # @param public_pem [String] SPKI-encoded public key PEM.
      # @param private_pem [String] PKCS#8-encoded private key PEM.
      # @return [Key] a full keypair.
      # @raise [KeyError] if the OIDs are unknown or the public and private
      #   PEMs specify different algorithms.
      def self.from_pem_pair(public_pem:, private_pem:)
        pub_info = PqcAsn1::DER.parse_pem(public_pem)
        priv_info = PqcAsn1::DER.parse_pem(private_pem)

        pub_alg = OID_TO_ALGORITHM[pub_info.oid]
        priv_alg = OID_TO_ALGORITHM[priv_info.oid]

        raise KeyError, "Unknown OID in public PEM: #{pub_info.oid.dotted}" unless pub_alg
        raise KeyError, "Unknown OID in private PEM: #{priv_info.oid.dotted}" unless priv_alg
        raise KeyError, "Algorithm mismatch: public=#{pub_alg}, private=#{priv_alg}" unless pub_alg == priv_alg

        sk_bytes = extract_secure_bytes(priv_info.key)
        new(algorithm: pub_alg, public_key: pub_info.key, private_key: sk_bytes)
      ensure
        priv_info&.key&.wipe!
      end

      # Export the public key as an SPKI PEM string.
      #
      # @return [String] a `-----BEGIN PUBLIC KEY-----` PEM document.
      def to_pem
        oid = ALGORITHM_OIDS[@algorithm]
        der = PqcAsn1::DER.build_spki(oid, @public_key)
        PqcAsn1::PEM.encode(der, "PUBLIC KEY")
      end

      # Export the private key as a PKCS#8 PEM string.
      #
      # The PEM carries both the private key and the public key (so the pair
      # can later be re-imported with {.from_pem} alone).
      #
      # @return [String] a `-----BEGIN PRIVATE KEY-----` PEM document.
      # @raise [KeyError] if this key has no private component.
      def private_to_pem
        raise KeyError, "Private key not available" unless @private_key

        oid = ALGORITHM_OIDS[@algorithm]
        secure_der = PqcAsn1::DER.build_pkcs8(oid, @private_key, public_key: @public_key)
        secure_der.to_pem
      end

      # @api private
      def self.resolve_algorithm(algorithm)
        ALGORITHM_ALIASES.fetch(algorithm.to_sym) { algorithm.to_s }
      end

      # @api private
      #
      # Extract bytes from a PqcAsn1::SecureBuffer using the safe block API.
      # The yielded String shares the SecureBuffer's C-level memory, so
      # String.new / dup / b all get zeroed when the block exits.
      # bytes.bytes.pack creates a fully independent copy via integer array.
      def self.extract_secure_bytes(secure_buffer)
        secure_buffer.use { |bytes| bytes.bytes.pack("C*") }
      end

      # @api private
      def self.resolve_oid!(oid)
        OID_TO_ALGORITHM[oid] || raise(KeyError, "Unknown OID in PEM: #{oid.dotted}")
      end

      # @api private
      def self.build_from_pkcs8(info, alg_name)
        raise KeyError, "PKCS#8 PEM for #{alg_name} missing public key. Use from_pem_pair." unless info.public_key

        sk_bytes = extract_secure_bytes(info.key)
        new(algorithm: alg_name, public_key: info.public_key, private_key: sk_bytes)
      end

      private_class_method :resolve_algorithm, :extract_secure_bytes, :resolve_oid!, :build_from_pkcs8

      private

      def sk_buffer
        @sk_buffer ||= FFI::MemoryPointer.new(:uint8, @private_key.bytesize).put_bytes(0, @private_key)
      end

      def pk_buffer
        @pk_buffer ||= FFI::MemoryPointer.new(:uint8, @public_key.bytesize).put_bytes(0, @public_key)
      end

      def resolve_algorithm(algorithm)
        self.class.send(:resolve_algorithm, algorithm)
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
