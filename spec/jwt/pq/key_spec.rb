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

  describe "#inspect" do
    let(:key) { described_class.generate(:ml_dsa_44) }

    it "does not expose private key material" do
      output = key.inspect
      expect(output).to include("ML-DSA-44")
      expect(output).to include("private=true")
      expect(output).not_to include(key.private_key)
    end

    it "works for public-only keys" do
      pub_key = described_class.from_public_key(:ml_dsa_44, key.public_key)
      expect(pub_key.inspect).to include("private=false")
    end

    it "is used by to_s" do
      expect(key.to_s).to eq(key.inspect)
    end
  end

  describe "#destroy!" do
    let(:key) { described_class.generate(:ml_dsa_44) }

    it "zeros and removes the private key" do
      expect(key).to be_private
      key.destroy!
      expect(key).not_to be_private
      expect(key.private_key).to be_nil
    end

    it "prevents signing after destroy" do
      key.destroy!
      expect { key.sign("data") }.to raise_error(JWT::PQ::KeyError, /Private key/)
    end

    it "still allows verification after destroy" do
      sig = key.sign("data")
      key.destroy!
      expect(key.verify("data", sig)).to be true
    end

    it "is safe to call on a public-only key" do
      pub_key = described_class.from_public_key(:ml_dsa_44, key.public_key)
      expect(pub_key.destroy!).to be true
    end
  end
end
