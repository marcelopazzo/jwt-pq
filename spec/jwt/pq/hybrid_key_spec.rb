# frozen_string_literal: true

require "ed25519"

RSpec.describe JWT::PQ::HybridKey do
  describe ".generate" do
    it "creates a hybrid key with default ML-DSA-65" do
      key = described_class.generate
      expect(key.algorithm).to eq("ML-DSA-65")
      expect(key.hybrid_algorithm).to eq("EdDSA+ML-DSA-65")
      expect(key).to be_private
    end

    JWT::PQ::MlDsa::ALGORITHMS.each_key do |alg_name|
      it "creates a hybrid key with #{alg_name}" do
        symbol = alg_name.downcase.tr("-", "_").to_sym
        key = described_class.generate(symbol)
        expect(key.algorithm).to eq(alg_name)
        expect(key.hybrid_algorithm).to eq("EdDSA+#{alg_name}")
      end
    end
  end

  describe ".new" do
    let(:ed_key) { Ed25519::SigningKey.generate }
    let(:ml_key) { JWT::PQ::Key.generate(:ml_dsa_44) }

    it "accepts an Ed25519::SigningKey" do
      key = described_class.new(ed25519: ed_key, ml_dsa: ml_key)
      expect(key.ed25519_signing_key).to eq(ed_key)
      expect(key.ed25519_verify_key).to eq(ed_key.verify_key)
      expect(key).to be_private
    end

    it "accepts an Ed25519::VerifyKey (verification only)" do
      key = described_class.new(ed25519: ed_key.verify_key, ml_dsa: ml_key)
      expect(key.ed25519_signing_key).to be_nil
      expect(key.ed25519_verify_key).to eq(ed_key.verify_key)
      expect(key).not_to be_private
    end

    it "is not private when ML-DSA key has no private component" do
      pub_ml = JWT::PQ::Key.from_public_key(:ml_dsa_44, ml_key.public_key)
      key = described_class.new(ed25519: ed_key, ml_dsa: pub_ml)
      expect(key).not_to be_private
    end

    it "raises for invalid Ed25519 key type" do
      expect { described_class.new(ed25519: "not a key", ml_dsa: ml_key) }
        .to raise_error(JWT::PQ::KeyError, /Ed25519/)
    end
  end

  describe "#inspect" do
    let(:key) { described_class.generate(:ml_dsa_44) }

    it "does not expose key material" do
      output = key.inspect
      expect(output).to include("EdDSA+ML-DSA-44")
      expect(output).to include("private=true")
      expect(output).not_to include(key.ml_dsa_key.private_key)
    end

    it "is used by to_s" do
      expect(key.to_s).to eq(key.inspect)
    end
  end
end
