# frozen_string_literal: true

module JWT
  module PQ
    # @api private
    #
    # Ruby wrapper around liboqs ML-DSA operations.
    # Handles memory allocation, FFI calls, and cleanup.
    class MlDsa
      ALGORITHMS = {
        "ML-DSA-44" => { public_key: 1312, secret_key: 2560, signature: 2420, nist_level: 2 },
        "ML-DSA-65" => { public_key: 1952, secret_key: 4032, signature: 3309, nist_level: 3 },
        "ML-DSA-87" => { public_key: 2592, secret_key: 4896, signature: 4627, nist_level: 5 }
      }.freeze

      @sign_handles = {}
      @sign_handles_mutex = Mutex.new

      def self.sign_handle(algorithm)
        @sign_handles[algorithm] || @sign_handles_mutex.synchronize do
          @sign_handles[algorithm] ||= begin
            h = LibOQS.OQS_SIG_new(algorithm)
            raise LiboqsError, "Failed to initialize #{algorithm}" if h.null?

            h
          end
        end
      end

      @verify_handles = {}
      @verify_handles_mutex = Mutex.new

      def self.verify_handle(algorithm)
        @verify_handles[algorithm] || @verify_handles_mutex.synchronize do
          @verify_handles[algorithm] ||= begin
            h = LibOQS.OQS_SIG_new(algorithm)
            raise LiboqsError, "Failed to initialize #{algorithm}" if h.null?

            h
          end
        end
      end

      # Drop the process-wide cache of `OQS_SIG` handles.
      #
      # The first call to {.sign_handle} or {.verify_handle} in a process
      # (or after this reset) lazily allocates a fresh handle. The
      # inherited handles in the child are not explicitly freed — doing
      # so can confuse `malloc` bookkeeping across forked processes. The
      # handles leak until process exit (≤3 algorithms × <1 KB each),
      # which is negligible.
      #
      # Prefer the public {JWT::PQ.reset_handles!} wrapper from
      # application code.
      #
      # @api private
      # @return [void]
      def self.reset_handles!
        @sign_handles_mutex.synchronize { @sign_handles.clear }
        @verify_handles_mutex.synchronize { @verify_handles.clear }
      end

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

        sk_buf = FFI::MemoryPointer.new(:uint8, secret_key.bytesize)
        sk_buf.put_bytes(0, secret_key)
        sign_with_sk_buffer(message, sk_buf)
      ensure
        sk_buf&.clear
      end

      # Faster sign path: takes a pre-populated FFI::MemoryPointer holding the
      # secret key. Caller is responsible for buffer lifecycle (allocation,
      # zeroing). Used by JWT::PQ::Key to avoid re-allocating+copying the
      # secret key on every sign call.
      def sign_with_sk_buffer(message, sk_buf)
        sig = self.class.sign_handle(@algorithm)
        sig_buf = FFI::MemoryPointer.new(:uint8, @sizes[:signature])
        sig_len = FFI::MemoryPointer.new(:size_t)
        msg_buf = FFI::MemoryPointer.from_string(message)

        status = LibOQS.OQS_SIG_sign(sig, sig_buf, sig_len,
                                     msg_buf, message.bytesize, sk_buf)
        raise SignatureError, "Signing failed for #{@algorithm}" unless status == LibOQS::OQS_SUCCESS

        sig_buf.read_bytes(sig_len.read(:size_t))
      end

      # Verify a signature against a message and public key.
      # Returns true if valid, false otherwise.
      def verify(message, signature, public_key)
        validate_key_size!(public_key, :public_key)

        pk_buf = FFI::MemoryPointer.new(:uint8, public_key.bytesize)
        pk_buf.put_bytes(0, public_key)
        verify_with_pk_buffer(message, signature, pk_buf)
      end

      # Faster verify path: takes a pre-populated FFI::MemoryPointer holding
      # the public key. Caller is responsible for buffer lifecycle. Used by
      # JWT::PQ::Key to avoid re-allocating+copying the public key on every
      # verify call.
      def verify_with_pk_buffer(message, signature, pk_buf)
        sig = self.class.verify_handle(@algorithm)
        msg_buf = FFI::MemoryPointer.from_string(message)
        sig_buf = FFI::MemoryPointer.new(:uint8, signature.bytesize)
        sig_buf.put_bytes(0, signature)

        status = LibOQS.OQS_SIG_verify(sig, msg_buf, message.bytesize,
                                       sig_buf, signature.bytesize, pk_buf)
        status == LibOQS::OQS_SUCCESS
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
