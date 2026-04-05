# frozen_string_literal: true

require "ffi"

module JWT
  module PQ
    # FFI bindings for liboqs signature operations.
    #
    # Library search order:
    #   1. OQS_LIB environment variable (explicit path)
    #   2. Vendored liboqs (compiled during gem install)
    #   3. System-installed liboqs (via standard library search)
    module LibOQS
      extend FFI::Library

      OQS_SUCCESS = 0
      OQS_ERROR = -1

      def self.lib_path
        # 1. Explicit path from environment
        return ENV["OQS_LIB"] if ENV["OQS_LIB"]

        # 2. Vendored library (compiled during gem install)
        vendored = vendored_lib_path
        return vendored if vendored

        # 3. System library
        "oqs"
      end

      def self.vendored_lib_path
        %w[dylib so].each do |ext|
          path = File.join(__dir__, "vendor", "lib", "liboqs.#{ext}")
          return path if File.exist?(path)
        end
        nil
      end
      private_class_method :vendored_lib_path

      begin
        ffi_lib lib_path
      rescue LoadError => e
        raise JWT::PQ::LiboqsError,
              "liboqs not found. The vendored library may not have been compiled " \
              "during gem install. Ensure cmake and a C compiler are installed, " \
              "then reinstall: gem install jwt-pq. Alternatively, install liboqs " \
              "manually and set OQS_LIB to the full path. " \
              "Original error: #{e.message}"
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
