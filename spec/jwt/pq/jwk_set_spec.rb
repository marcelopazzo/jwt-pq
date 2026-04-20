# frozen_string_literal: true

require "json"

RSpec.describe JWT::PQ::JWKSet do
  let(:key_a) { JWT::PQ::Key.generate(:ml_dsa_44) }
  let(:key_b) { JWT::PQ::Key.generate(:ml_dsa_65) }
  let(:key_c) { JWT::PQ::Key.generate(:ml_dsa_87) }

  let(:kid_a) { JWT::PQ::JWK.new(key_a).thumbprint }
  let(:kid_b) { JWT::PQ::JWK.new(key_b).thumbprint }

  describe "#initialize" do
    it "accepts an empty array" do
      set = described_class.new
      expect(set).to be_empty
      expect(set.size).to eq(0)
    end

    it "accepts an array of keys" do
      set = described_class.new([key_a, key_b])
      expect(set.size).to eq(2)
    end

    it "accepts a single key (wrapped via Array())" do
      set = described_class.new(key_a)
      expect(set.size).to eq(1)
    end

    it "raises for non-Key members" do
      expect { described_class.new(["not a key"]) }
        .to raise_error(JWT::PQ::KeyError, /JWT::PQ::Key/)
    end
  end

  describe "#add" do
    let(:set) { described_class.new }

    it "returns self for chaining" do
      expect(set.add(key_a)).to equal(set)
    end

    it "increments size" do
      set.add(key_a).add(key_b)
      expect(set.size).to eq(2)
    end

    it "rejects non-Key inputs" do
      expect { set.add("nope") }.to raise_error(JWT::PQ::KeyError, /JWT::PQ::Key/)
    end

    it "is idempotent on duplicate kid (same key instance)" do
      set.add(key_a).add(key_a)
      expect(set.size).to eq(1)
      expect(set[kid_a]).to equal(key_a)
    end

    it "is idempotent on duplicate kid (equivalent public key, different instance)" do
      twin = JWT::PQ::Key.from_public_key(:ml_dsa_44, key_a.public_key)
      set.add(key_a).add(twin)
      expect(set.size).to eq(1)
      expect(set[kid_a]).to equal(key_a)
    end
  end

  describe "lookup" do
    let(:set) { described_class.new([key_a, key_b]) }

    it "finds a key by thumbprint via #find" do
      expect(set.find(kid_a)).to equal(key_a)
      expect(set.find(kid_b)).to equal(key_b)
    end

    it "exposes #[] as an alias for #find" do
      expect(set[kid_a]).to equal(key_a)
    end

    it "returns nil for unknown kid" do
      expect(set.find("unknown")).to be_nil
    end
  end

  describe "enumeration" do
    let(:set) { described_class.new([key_a, key_b, key_c]) }

    it "includes Enumerable" do
      expect(set).to be_a(Enumerable)
    end

    it "iterates in insertion order" do
      expect(set.to_a).to eq([key_a, key_b, key_c])
    end

    it "returns an Enumerator without a block" do
      expect(set.each).to be_a(Enumerator)
    end

    it "#keys returns a frozen snapshot" do
      snapshot = set.keys
      expect(snapshot).to eq([key_a, key_b, key_c])
      expect(snapshot).to be_frozen
    end
  end

  describe "#export" do
    let(:set) { described_class.new([key_a, key_b]) }

    it "returns a JWKS hash with public-only keys by default" do
      jwks = set.export
      expect(jwks).to have_key(:keys)
      expect(jwks[:keys].size).to eq(2)
      jwks[:keys].each do |jwk|
        expect(jwk[:kty]).to eq("AKP")
        expect(jwk).not_to have_key(:priv)
      end
    end

    it "includes priv when requested" do
      jwks = set.export(include_private: true)
      jwks[:keys].each { |jwk| expect(jwk[:priv]).to be_a(String) }
    end

    it "omits priv on public-only members even when requested" do
      pub_key = JWT::PQ::Key.from_public_key(:ml_dsa_44, key_a.public_key)
      pub_set = described_class.new([pub_key])
      jwks = pub_set.export(include_private: true)
      expect(jwks[:keys].first).not_to have_key(:priv)
    end
  end

  describe "#to_json" do
    let(:set) { described_class.new([key_a]) }

    it "produces valid JSON with a keys array" do
      parsed = JSON.parse(set.to_json)
      expect(parsed["keys"].size).to eq(1)
      expect(parsed["keys"].first["kty"]).to eq("AKP")
    end

    it "omits priv by default" do
      parsed = JSON.parse(set.to_json)
      expect(parsed["keys"].first).not_to have_key("priv")
    end

    it "emits private material via JSON.generate(set.export(include_private: true))" do
      parsed = JSON.parse(JSON.generate(set.export(include_private: true)))
      expect(parsed["keys"].first["priv"]).to be_a(String)
    end

    it "serializes correctly when nested inside another Hash" do
      wrapped = { jwks: set }.to_json
      parsed = JSON.parse(wrapped)
      expect(parsed["jwks"]["keys"].size).to eq(1)
      expect(parsed["jwks"]["keys"].first["kty"]).to eq("AKP")
    end

    it "never leaks priv when nested, even when the set owns private keys" do
      wrapped = { jwks: set }.to_json
      expect(wrapped).not_to include("\"priv\"")
    end
  end

  describe "#inspect" do
    it "reports size without exposing key material" do
      set = described_class.new([key_a, key_b])
      expect(set.inspect).to eq("#<JWT::PQ::JWKSet size=2>")
    end
  end

  describe ".import" do
    let(:original) { described_class.new([key_a, key_b]) }

    it "round-trips public-only JWKS via a Hash" do
      restored = described_class.import(original.export)
      expect(restored.size).to eq(2)
      expect(restored[kid_a].public_key).to eq(key_a.public_key)
      expect(restored[kid_a]).not_to be_private
    end

    it "round-trips JWKS with private keys" do
      restored = described_class.import(original.export(include_private: true))
      expect(restored[kid_a]).to be_private
      expect(restored[kid_a].private_key).to eq(key_a.private_key)
    end

    it "accepts a JSON string" do
      restored = described_class.import(original.to_json)
      expect(restored.size).to eq(2)
      expect(restored[kid_a].public_key).to eq(key_a.public_key)
    end

    it "accepts string-keyed hashes" do
      stringified = original.export.transform_keys(&:to_s)
      stringified["keys"] = stringified["keys"].map { |k| k.transform_keys(&:to_s) }
      restored = described_class.import(stringified)
      expect(restored.size).to eq(2)
    end

    it "raises for an unsupported source type" do
      expect { described_class.import(42) }
        .to raise_error(JWT::PQ::KeyError, /Expected Hash or JSON String/)
    end

    it "raises when 'keys' is missing" do
      expect { described_class.import({}) }
        .to raise_error(JWT::PQ::KeyError, /Missing 'keys'/)
    end

    it "raises when 'keys' is not an Array" do
      expect { described_class.import({ "keys" => "nope" }) }
        .to raise_error(JWT::PQ::KeyError, /must be an Array/)
    end

    it "propagates JWK-level errors from members" do
      expect { described_class.import({ "keys" => [{ "kty" => "RSA" }] }) }
        .to raise_error(JWT::PQ::KeyError, /kty/)
    end
  end

  describe "consumer flow — resolve verification key by kid" do
    let(:payload) { { "sub" => "jwks-test" } }

    it "verifies a JWT using a key fetched from the set by kid" do
      token = JWT.encode(payload, key_b, "ML-DSA-65", { kid: kid_b })
      _, header = JWT.decode(token, nil, false)
      set = described_class.new([key_a, key_b])

      verification_key = set[header["kid"]]
      expect(verification_key).not_to be_nil

      decoded, = JWT.decode(token, verification_key, true, algorithms: ["ML-DSA-65"])
      expect(decoded).to eq(payload)
    end

    it "returns nil when the JWT kid is not in the set" do
      foreign_kid = JWT::PQ::JWK.new(key_c).thumbprint
      token = JWT.encode(payload, key_c, "ML-DSA-87", { kid: foreign_kid })
      _, header = JWT.decode(token, nil, false)

      set = described_class.new([key_a, key_b])
      expect(set[header["kid"]]).to be_nil
    end
  end
end
