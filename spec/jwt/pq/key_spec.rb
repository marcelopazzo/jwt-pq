# frozen_string_literal: true

RSpec.describe JWT::PQ::Key do
  JWT::PQ::MlDsa::ALGORITHMS.each_key do |alg_name|
    context "with #{alg_name}" do
      describe ".generate" do
        it "creates a key with both public and private components" do
          key = described_class.generate(alg_name)
          expect(key.public_key).not_to be_nil
          expect(key.private_key).not_to be_nil
          expect(key).to be_private
        end

        it "sets the correct algorithm name" do
          key = described_class.generate(alg_name)
          expect(key.algorithm).to eq(alg_name)
        end
      end

      describe ".generate with symbol alias" do
        let(:symbol_alias) { alg_name.downcase.tr("-", "_").to_sym }

        it "accepts symbol aliases" do
          key = described_class.generate(symbol_alias)
          expect(key.algorithm).to eq(alg_name)
        end
      end

      describe ".from_public_key" do
        let(:full_key) { described_class.generate(alg_name) }

        it "creates a verification-only key" do
          pub_key = described_class.from_public_key(alg_name, full_key.public_key)
          expect(pub_key.public_key).to eq(full_key.public_key)
          expect(pub_key.private_key).to be_nil
          expect(pub_key).not_to be_private
        end

        it "cannot sign" do
          pub_key = described_class.from_public_key(alg_name, full_key.public_key)
          expect { pub_key.sign("data") }.to raise_error(JWT::PQ::KeyError, /Private key/)
        end
      end

      describe "#sign and #verify" do
        let(:key) { described_class.generate(alg_name) }
        let(:message) { "payload to sign" }

        it "produces a verifiable signature" do
          sig = key.sign(message)
          expect(key.verify(message, sig)).to be true
        end

        it "rejects tampered data" do
          sig = key.sign(message)
          expect(key.verify("tampered", sig)).to be false
        end

        it "can verify with a public-key-only instance" do
          sig = key.sign(message)
          pub_only = described_class.from_public_key(alg_name, key.public_key)
          expect(pub_only.verify(message, sig)).to be true
        end
      end
    end
  end

  describe "validation" do
    it "raises KeyError for invalid public key size" do
      expect do
        described_class.new(algorithm: "ML-DSA-44", public_key: "x" * 10)
      end.to raise_error(JWT::PQ::KeyError, /public key size/)
    end

    it "raises KeyError for invalid private key size" do
      valid_pk = "\x00" * 1312
      expect do
        described_class.new(algorithm: "ML-DSA-44", public_key: valid_pk, private_key: "x" * 10)
      end.to raise_error(JWT::PQ::KeyError, /private key size/)
    end
  end
end
