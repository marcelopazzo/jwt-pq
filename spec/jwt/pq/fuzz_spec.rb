# frozen_string_literal: true

require "base64"
require "json"

# Bounded-reproducible fuzz for the untrusted-input parsers.
#
# Anything reaching JWK/JWKS import from the wire (HTTP, disk, user
# payload) is attacker-influenced. The contract is that malformed
# input only ever surfaces as JWT::PQ::KeyError — never NoMethodError,
# TypeError, ArgumentError, JSON::ParserError, or an FFI crash.
#
# Deterministic seed so failures are reproducible; batch reporting so
# all broken mutators surface in a single run.
FUZZ_SEED = 42
FUZZ_ITERATIONS = 5

RSpec.describe "Fuzz: parsing untrusted JWK / JWKS input" do
  let(:rng) { Random.new(FUZZ_SEED) }
  let(:valid_jwk) do
    key = JWT::PQ::Key.generate(:ml_dsa_65)
    JWT::PQ::JWK.new(key).export(include_private: true)
  end

  def random_bytes(prng, count)
    Array.new(count) { prng.rand(256) }.pack("C*")
  end

  def b64(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def run_fuzz(mutators)
    failures = []
    mutators.each_with_index do |mutator, i|
      FUZZ_ITERATIONS.times do |j|
        input = mutator.call
        begin
          yield input
        rescue JWT::PQ::KeyError
          # expected
        rescue StandardError => e
          failures << "mutator=#{i} iter=#{j} input=#{input.inspect[0, 80]} " \
                      "raised #{e.class}: #{e.message.to_s.lines.first&.strip}"
        end
      end
    end
    failures
  end

  describe "JWT::PQ::JWK.import" do
    it "only surfaces JWT::PQ::KeyError for malformed inputs" do
      base = valid_jwk
      r = rng
      mutators = [
        # Non-Hash inputs
        -> {},
        -> { 42 },
        -> { "string" },
        -> { [] },
        -> { [1, 2, 3] },
        -> { true },
        -> { Object.new },
        -> { JSON.generate(base) },

        # Empty / missing required fields
        -> { {} },
        -> { base.dup.tap { |h| h.delete(:kty) } },
        -> { base.dup.tap { |h| h.delete(:alg) } },
        -> { base.dup.tap { |h| h.delete(:pub) } },

        # Wrong types for kty
        -> { base.merge(kty: r.rand(1_000_000)) },
        -> { base.merge(kty: []) },
        -> { base.merge(kty: {}) },
        -> { base.merge(kty: nil) },

        # Wrong types for alg
        -> { base.merge(alg: r.rand(1_000_000)) },
        -> { base.merge(alg: [base[:alg]]) },
        -> { base.merge(alg: nil) },
        -> { base.merge(alg: {}) },

        # Wrong types for pub
        -> { base.merge(pub: r.rand(1_000_000)) },
        -> { base.merge(pub: nil) },
        -> { base.merge(pub: [base[:pub]]) },
        -> { base.merge(pub: {}) },

        # Invalid values
        -> { base.merge(kty: "RSA") },
        -> { base.merge(alg: "HS256") },
        -> { base.merge(pub: "!@#$%not-base64") },
        -> { base.merge(pub: "") },
        -> { base.merge(priv: "!@#$%not-base64") },
        -> { base.merge(priv: nil) },
        -> { base.merge(priv: []) },

        # Truncation / corruption of pub
        -> { base.merge(pub: base[:pub][0..5]) },
        -> { base.merge(pub: "#{base[:pub]}XYZ") },
        -> { base.merge(pub: b64(random_bytes(r, 10))) },
        -> { base.merge(pub: b64(random_bytes(r, 100_000))) },

        # Unicode / null bytes
        -> { base.merge(alg: "ML-DSA-65\x00") },
        -> { base.merge(alg: "ML-DSA-65\u{1F389}") },
        -> { base.merge(kty: "AKP\x00") },

        # Random noise
        -> { { kty: random_bytes(r, 8), alg: random_bytes(r, 8), pub: random_bytes(r, 32) } }
      ]

      failures = run_fuzz(mutators) { |input| JWT::PQ::JWK.import(input) }
      expect(failures).to be_empty, "Unexpected exceptions:\n#{failures.join("\n")}"
    end
  end

  describe "JWT::PQ::JWKSet.import" do
    it "only surfaces JWT::PQ::KeyError for malformed inputs" do
      jwk = valid_jwk.dup.tap { |h| h.delete(:priv) }
      mutators = [
        # Non-Hash/String
        -> {},
        -> { 42 },
        -> { [] },
        -> { Object.new },
        -> { true },

        # Invalid JSON
        -> { "not valid json" },
        -> { "{" },
        -> { '{"keys":' },
        -> { "" },

        # Valid JSON, wrong top-level shape
        -> { "42" },
        -> { "null" },
        -> { "[]" },
        -> { "\"string\"" },
        -> { "true" },

        # Hash but missing / malformed 'keys'
        -> { {} },
        -> { { "keys" => "not an array" } },
        -> { { "keys" => nil } },
        -> { { "keys" => 42 } },
        -> { { "keys" => {} } },

        # keys array with non-Hash members
        -> { { "keys" => [1, 2, 3] } },
        -> { { "keys" => [nil] } },
        -> { { "keys" => ["string1"] } },
        -> { { "keys" => [[]] } },

        # JSON-encoded versions of the above
        -> { '{"keys":[1,2,3]}' },
        -> { '{"keys":[null]}' },
        -> { '{"keys":[{"kty":"RSA"}]}' },
        -> { '{"keys":[{}]}' },

        # Partially valid (mix)
        -> { { "keys" => [jwk, { "kty" => "bad" }] } },
        -> { { "keys" => [jwk, nil] } }
      ]

      failures = run_fuzz(mutators) { |input| JWT::PQ::JWKSet.import(input) }
      expect(failures).to be_empty, "Unexpected exceptions:\n#{failures.join("\n")}"
    end
  end
end
