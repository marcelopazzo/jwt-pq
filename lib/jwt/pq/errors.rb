# frozen_string_literal: true

module JWT
  module PQ
    class Error < StandardError; end

    class LiboqsError < Error; end

    class UnsupportedAlgorithmError < Error; end

    class KeyError < Error; end

    class MissingDependencyError < Error; end

    class SignatureError < Error; end
  end
end
