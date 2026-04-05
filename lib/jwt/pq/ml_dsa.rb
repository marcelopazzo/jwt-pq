# frozen_string_literal: true

module JWT
  module PQ
    # Ruby wrapper around liboqs ML-DSA operations.
    # Handles memory allocation, FFI calls, and cleanup.
    class MlDsa
      ALGORITHMS = {
        "ML-DSA-44" => { public_key: 1312, secret_key: 2560, signature: 2420, nist_level: 2 },
        "ML-DSA-65" => { public_key: 1952, secret_key: 4032, signature: 3309, nist_level: 3 },
        "ML-DSA-87" => { public_key: 2592, secret_key: 4896, signature: 4627, nist_level: 5 }
      }.freeze

      attr_reader :algorithm

      def initialize(algorithm)
        algorithm = algorithm.to_s
        unless ALGORITHMS.key?(algorithm)
          raise UnsupportedAlgorithmError,
                "Unsupported algorithm: #{algorithm}. " \
                "Supported: #{ALGORITHMS.keys.join(", ")}"
        end

        @algorithm = algorithm
        @sizes = ALGORITHMS[algorithm]
      end

      # Generate a new keypair.
      # Returns [public_key_bytes, secret_key_bytes]
      def keypair
        sig = LibOQS.OQS_SIG_new(@algorithm)
        raise LiboqsError, "Failed to initialize #{@algorithm}" if sig.null?

        pk = FFI::MemoryPointer.new(:uint8, @sizes[:public_key])
        sk = FFI::MemoryPointer.new(:uint8, @sizes[:secret_key])

        status = LibOQS.OQS_SIG_keypair(sig, pk, sk)
        raise LiboqsError, "Keypair generation failed for #{@algorithm}" unless status == LibOQS::OQS_SUCCESS

        [pk.read_bytes(@sizes[:public_key]), sk.read_bytes(@sizes[:secret_key])]
      ensure
        sk&.clear
        LibOQS.OQS_SIG_free(sig) if sig && !sig.null?
      end

      # Sign a message with a secret key.
      # Returns the signature bytes.
      def sign(message, secret_key)
        validate_key_size!(secret_key, :secret_key)

        sig = LibOQS.OQS_SIG_new(@algorithm)
        raise LiboqsError, "Failed to initialize #{@algorithm}" if sig.null?

        sig_buf = FFI::MemoryPointer.new(:uint8, @sizes[:signature])
        sig_len = FFI::MemoryPointer.new(:size_t)
        msg_buf = FFI::MemoryPointer.from_string(message)
        sk_buf = FFI::MemoryPointer.new(:uint8, secret_key.bytesize)
        sk_buf.put_bytes(0, secret_key)

        status = LibOQS.OQS_SIG_sign(sig, sig_buf, sig_len,
                                     msg_buf, message.bytesize, sk_buf)
        raise SignatureError, "Signing failed for #{@algorithm}" unless status == LibOQS::OQS_SUCCESS

        actual_len = sig_len.read(:size_t)
        sig_buf.read_bytes(actual_len)
      ensure
        sk_buf&.clear
        LibOQS.OQS_SIG_free(sig) if sig && !sig.null?
      end

      # Verify a signature against a message and public key.
      # Returns true if valid, false otherwise.
      def verify(message, signature, public_key)
        validate_key_size!(public_key, :public_key)

        sig = LibOQS.OQS_SIG_new(@algorithm)
        raise LiboqsError, "Failed to initialize #{@algorithm}" if sig.null?

        msg_buf = FFI::MemoryPointer.from_string(message)
        sig_buf = FFI::MemoryPointer.new(:uint8, signature.bytesize)
        sig_buf.put_bytes(0, signature)
        pk_buf = FFI::MemoryPointer.new(:uint8, public_key.bytesize)
        pk_buf.put_bytes(0, public_key)

        status = LibOQS.OQS_SIG_verify(sig, msg_buf, message.bytesize,
                                       sig_buf, signature.bytesize, pk_buf)
        status == LibOQS::OQS_SUCCESS
      ensure
        LibOQS.OQS_SIG_free(sig) if sig && !sig.null?
      end

      # Key sizes for this algorithm
      def public_key_size
        @sizes[:public_key]
      end

      def secret_key_size
        @sizes[:secret_key]
      end

      def signature_size
        @sizes[:signature]
      end

      private

      def validate_key_size!(key, type)
        expected = @sizes[type]
        return if key.bytesize == expected

        raise KeyError,
              "Invalid #{type} size for #{@algorithm}: " \
              "expected #{expected} bytes, got #{key.bytesize}"
      end
    end
  end
end
