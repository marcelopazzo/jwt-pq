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

    it "raises MissingDependencyError when ed25519 is not available" do
      allow(described_class).to receive(:require).with("ed25519").and_raise(LoadError)
      expect { described_class.generate }.to raise_error(JWT::PQ::MissingDependencyError, /jwt-eddsa/)
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

  describe "#destroy!" do
    let(:key) { described_class.generate(:ml_dsa_44) }

    it "zeros both key components" do
      expect(key).to be_private
      key.destroy!
      expect(key).not_to be_private
      expect(key.ed25519_signing_key).to be_nil
      expect(key.ml_dsa_key).not_to be_private
    end

    it "prevents signing after destroy" do
      key.destroy!
      expect do
        JWT.encode({ "sub" => "1" }, key, "EdDSA+ML-DSA-44")
      end.to raise_error(JWT::EncodeError)
    end

    it "is safe to call on a verify-only key" do
      verify_key = described_class.new(
        ed25519: key.ed25519_verify_key,
        ml_dsa: JWT::PQ::Key.from_public_key(:ml_dsa_44, key.ml_dsa_key.public_key)
      )
      expect(verify_key.destroy!).to be true
    end

    it "zeros the Ed25519 seed (@seed) in place" do
      ed_sk = Ed25519::SigningKey.generate
      hybrid = described_class.new(
        ed25519: ed_sk,
        ml_dsa: JWT::PQ::Key.generate(:ml_dsa_44)
      )

      hybrid.destroy!

      expect(ed_sk.to_bytes).to eq("\0" * 32)
    end

    it "zeros the Ed25519 @keypair (seed || public_key) in place" do
      ed_sk = Ed25519::SigningKey.generate
      hybrid = described_class.new(
        ed25519: ed_sk,
        ml_dsa: JWT::PQ::Key.generate(:ml_dsa_44)
      )
      # Capture the internal keypair String before destroy so we can verify
      # the live object (attr_reader returns the ivar by reference) got wiped.
      keypair_ref = ed_sk.keypair
      expect(keypair_ref.bytesize).to eq(64)

      hybrid.destroy!

      expect(keypair_ref).to eq("\0" * 64)
      expect(ed_sk.keypair).to eq("\0" * 64)
    end
  end
end
