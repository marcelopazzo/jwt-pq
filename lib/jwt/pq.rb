# frozen_string_literal: true

require_relative "pq/version"
require_relative "pq/errors"
require_relative "pq/liboqs"
require_relative "pq/ml_dsa"
require_relative "pq/key"
require_relative "pq/algorithms/ml_dsa"
require_relative "pq/hybrid_key"
require_relative "pq/algorithms/hybrid_eddsa"

module JWT
  module PQ
    # Whether jwt-eddsa / ed25519 is available for hybrid mode.
    def self.hybrid_available?
      require "ed25519"
      true
    rescue LoadError
      false
    end
  end
end
