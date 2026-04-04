# frozen_string_literal: true

RSpec.describe JWT::PQ::MlDsa do
  described_class::ALGORITHMS.each_key do |alg_name|
    context "with #{alg_name}" do
      subject(:ml_dsa) { described_class.new(alg_name) }

      let(:sizes) { described_class::ALGORITHMS[alg_name] }

      describe "#keypair" do
        it "generates keys of the correct sizes" do
          pk, sk = ml_dsa.keypair
          expect(pk.bytesize).to eq(sizes[:public_key])
          expect(sk.bytesize).to eq(sizes[:secret_key])
        end

        it "generates different keypairs each time" do
          pk1, = ml_dsa.keypair
          pk2, = ml_dsa.keypair
          expect(pk1).not_to eq(pk2)
        end
      end

      describe "#sign" do
        let(:keypair) { ml_dsa.keypair }
        let(:public_key) { keypair[0] }
        let(:secret_key) { keypair[1] }

        it "produces a signature within expected size" do
          sig = ml_dsa.sign("test message", secret_key)
          expect(sig.bytesize).to be <= sizes[:signature]
          expect(sig.bytesize).to be > 0
        end

        it "produces different signatures for different messages" do
          sig1 = ml_dsa.sign("message one", secret_key)
          sig2 = ml_dsa.sign("message two", secret_key)
          expect(sig1).not_to eq(sig2)
        end

        it "raises KeyError for wrong-size secret key" do
          expect { ml_dsa.sign("msg", "short") }.to raise_error(JWT::PQ::KeyError, /secret_key/)
        end
      end

      describe "#verify" do
        let(:keypair) { ml_dsa.keypair }
        let(:public_key) { keypair[0] }
        let(:secret_key) { keypair[1] }
        let(:message) { "test message for verification" }
        let(:signature) { ml_dsa.sign(message, secret_key) }

        it "returns true for a valid signature" do
          expect(ml_dsa.verify(message, signature, public_key)).to be true
        end

        it "returns false for a tampered message" do
          expect(ml_dsa.verify("tampered message", signature, public_key)).to be false
        end

        it "returns false for a tampered signature" do
          bad_sig = signature.dup
          bad_sig.setbyte(0, (bad_sig.getbyte(0) + 1) % 256)
          expect(ml_dsa.verify(message, bad_sig, public_key)).to be false
        end

        it "returns false for a different public key" do
          other_pk, = ml_dsa.keypair
          expect(ml_dsa.verify(message, signature, other_pk)).to be false
        end

        it "raises KeyError for wrong-size public key" do
          expect { ml_dsa.verify(message, signature, "short") }.to raise_error(JWT::PQ::KeyError, /public_key/)
        end
      end

      describe "#sign and #verify with binary data" do
        it "handles binary message content" do
          _, sk = ml_dsa.keypair
          pk = ml_dsa.keypair[0] # different key to ensure independence
          pk, sk = ml_dsa.keypair

          binary_msg = (0..255).map(&:chr).join
          sig = ml_dsa.sign(binary_msg, sk)
          expect(ml_dsa.verify(binary_msg, sig, pk)).to be true
        end

        it "handles empty message" do
          pk, sk = ml_dsa.keypair
          sig = ml_dsa.sign("", sk)
          expect(ml_dsa.verify("", sig, pk)).to be true
        end
      end
    end
  end

  describe ".new" do
    it "raises UnsupportedAlgorithmError for unknown algorithm" do
      expect { described_class.new("ML-DSA-999") }.to raise_error(
        JWT::PQ::UnsupportedAlgorithmError, /ML-DSA-999/
      )
    end
  end
end
