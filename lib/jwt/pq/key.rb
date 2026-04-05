# frozen_string_literal: true

require "pqc_asn1"

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

      ALGORITHM_OIDS = {
        "ML-DSA-44" => PqcAsn1::OID::ML_DSA_44,
        "ML-DSA-65" => PqcAsn1::OID::ML_DSA_65,
        "ML-DSA-87" => PqcAsn1::OID::ML_DSA_87
      }.freeze

      OID_TO_ALGORITHM = ALGORITHM_OIDS.invert.freeze

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

      # Import a Key from a PEM string (SPKI or PKCS#8).
      def self.from_pem(pem_string)
        info = PqcAsn1::DER.parse_pem(pem_string)
        alg_name = resolve_oid!(info.oid)

        case info.format
        when :spki  then new(algorithm: alg_name, public_key: info.key)
        when :pkcs8 then build_from_pkcs8(info, alg_name)
        else raise KeyError, "Unsupported PEM format: #{info.format}"
        end
      ensure
        info&.key&.wipe! if info&.format == :pkcs8
      end

      # Import a Key from separate public and private PEM strings.
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

      # Export the public key as PEM (SPKI format).
      def to_pem
        oid = ALGORITHM_OIDS[@algorithm]
        der = PqcAsn1::DER.build_spki(oid, @public_key)
        PqcAsn1::PEM.encode(der, "PUBLIC KEY")
      end

      # Export the private key as PEM (PKCS#8 format).
      def private_to_pem
        raise KeyError, "Private key not available" unless @private_key

        oid = ALGORITHM_OIDS[@algorithm]
        secure_der = PqcAsn1::DER.build_pkcs8(oid, @private_key, public_key: @public_key)
        secure_der.to_pem
      end

      def self.resolve_algorithm(algorithm)
        ALGORITHM_ALIASES.fetch(algorithm.to_sym) { algorithm.to_s }
      end

      # Extract bytes from a PqcAsn1::SecureBuffer using the safe block API.
      # The yielded String shares the SecureBuffer's C-level memory, so
      # String.new / dup / b all get zeroed when the block exits.
      # bytes.bytes.pack creates a fully independent copy via integer array.
      def self.extract_secure_bytes(secure_buffer)
        secure_buffer.use { |bytes| bytes.bytes.pack("C*") }
      end

      def self.resolve_oid!(oid)
        OID_TO_ALGORITHM[oid] || raise(KeyError, "Unknown OID in PEM: #{oid.dotted}")
      end

      def self.build_from_pkcs8(info, alg_name)
        raise KeyError, "PKCS#8 PEM for #{alg_name} missing public key. Use from_pem_pair." unless info.public_key

        sk_bytes = extract_secure_bytes(info.key)
        new(algorithm: alg_name, public_key: info.public_key, private_key: sk_bytes)
      end

      private_class_method :extract_secure_bytes, :resolve_oid!, :build_from_pkcs8

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
