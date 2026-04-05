# frozen_string_literal: true

require "ffi"

module JWT
  module PQ
    # FFI bindings for liboqs signature operations.
    #
    # The library search order:
    #   1. OQS_LIB environment variable (explicit path)
    #   2. System-installed liboqs (via standard library search)
    module LibOQS
      extend FFI::Library

      OQS_SUCCESS = 0
      OQS_ERROR = -1

      # Determine library path
      def self.lib_path
        return ENV["OQS_LIB"] if ENV["OQS_LIB"]

        "oqs"
      end

      begin
        ffi_lib lib_path
      rescue LoadError => e
        raise JWT::PQ::LiboqsError,
              "liboqs not found. Install it via: brew install liboqs (macOS) or " \
              "apt install liboqs-dev (Ubuntu). You can also set OQS_LIB to the " \
              "full path of the shared library. Original error: #{e.message}"
      end

      # OQS_SIG *OQS_SIG_new(const char *method_name)
      attach_function :OQS_SIG_new, [:string], :pointer

      # void OQS_SIG_free(OQS_SIG *sig)
      attach_function :OQS_SIG_free, [:pointer], :void

      # OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key)
      attach_function :OQS_SIG_keypair, %i[pointer pointer pointer], :int

      # OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
      #                          const uint8_t *message, size_t message_len,
      #                          const uint8_t *secret_key)
      attach_function :OQS_SIG_sign, %i[pointer pointer pointer
                                        pointer size_t pointer], :int

      # OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message,
      #                            size_t message_len, const uint8_t *signature,
      #                            size_t signature_len, const uint8_t *public_key)
      attach_function :OQS_SIG_verify, %i[pointer pointer size_t
                                          pointer size_t pointer], :int
    end
  end
end
