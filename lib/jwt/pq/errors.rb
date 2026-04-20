# frozen_string_literal: true

module JWT
  module PQ
    # Base class for all jwt-pq errors.
    class Error < StandardError; end

    # Raised when liboqs reports a failure or is missing at load time.
    class LiboqsError < Error; end

    # Raised when a requested algorithm name is not supported.
    class UnsupportedAlgorithmError < Error; end

    # Raised for malformed keys, wrong key types, or invalid key material.
    class KeyError < Error; end

    # Raised when an optional runtime dependency (e.g. `ed25519` for hybrid
    # mode) is needed but not installed.
    class MissingDependencyError < Error; end

    # Raised when a signing operation fails inside liboqs.
    class SignatureError < Error; end
  end
end
