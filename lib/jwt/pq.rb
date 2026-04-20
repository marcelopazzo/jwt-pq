# frozen_string_literal: true

require_relative "pq/version"
require_relative "pq/errors"
require_relative "pq/liboqs"
require_relative "pq/ml_dsa"
require_relative "pq/key"
require_relative "pq/algorithms/ml_dsa"
require_relative "pq/jwk"
require_relative "pq/hybrid_key"
require_relative "pq/algorithms/hybrid_eddsa"

module JWT
  # Post-quantum signature support for the ruby-jwt ecosystem.
  #
  # Provides ML-DSA (FIPS 204) signatures as JWT algorithms `ML-DSA-44`,
  # `ML-DSA-65`, and `ML-DSA-87`, plus optional hybrid modes `EdDSA+ML-DSA-*`
  # that concatenate an Ed25519 signature with an ML-DSA signature.
  #
  # @example Encode a JWT with ML-DSA-65
  #   key = JWT::PQ::Key.generate(:ml_dsa_65)
  #   token = JWT.encode({ sub: "user-1" }, key, "ML-DSA-65")
  #
  # @example Decode and verify
  #   decoded, _header = JWT.decode(token, key, true, algorithms: ["ML-DSA-65"])
  #
  # @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf FIPS 204 (ML-DSA)
  # @see https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/ draft-ietf-cose-dilithium
  module PQ
    # Whether the `ed25519` (or `jwt-eddsa`) gem is available for hybrid mode.
    #
    # Hybrid `EdDSA+ML-DSA-*` algorithms require the `ed25519` gem at runtime.
    # This method probes for it without raising, so callers can decide whether
    # to offer hybrid options.
    #
    # @return [Boolean] true when `ed25519` can be required, false otherwise.
    def self.hybrid_available?
      require "ed25519"
      true
    rescue LoadError
      false
    end
  end
end
