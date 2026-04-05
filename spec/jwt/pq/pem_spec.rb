# frozen_string_literal: true

RSpec.describe "PEM serialization" do
  JWT::PQ::MlDsa::ALGORITHMS.each_key do |alg_name|
    context "with #{alg_name}" do
      let(:key) { JWT::PQ::Key.generate(alg_name) }

      describe "#to_pem" do
        it "exports a valid PEM public key" do
          pem = key.to_pem
          expect(pem).to start_with("-----BEGIN PUBLIC KEY-----")
          expect(pem).to end_with("-----END PUBLIC KEY-----\n")
        end

        it "round-trips through from_pem" do
          pem = key.to_pem
          restored = JWT::PQ::Key.from_pem(pem)

          expect(restored.algorithm).to eq(alg_name)
          expect(restored.public_key).to eq(key.public_key)
          expect(restored).not_to be_private
        end
      end

      describe "#private_to_pem" do
        it "exports a valid PEM private key" do
          pem = key.private_to_pem
          expect(pem).to start_with("-----BEGIN PRIVATE KEY-----")
          expect(pem).to end_with("-----END PRIVATE KEY-----\n")
        end

        it "raises when no private key is available" do
          pub_only = JWT::PQ::Key.from_public_key(alg_name, key.public_key)
          expect { pub_only.private_to_pem }.to raise_error(JWT::PQ::KeyError, /Private key/)
        end
      end

      describe ".from_pem_pair" do
        it "round-trips public + private PEM" do
          pub_pem = key.to_pem
          priv_pem = key.private_to_pem

          restored = JWT::PQ::Key.from_pem_pair(public_pem: pub_pem, private_pem: priv_pem)
          expect(restored.algorithm).to eq(alg_name)
          expect(restored.public_key).to eq(key.public_key)
          expect(restored.private_key).to eq(key.private_key)
          expect(restored).to be_private
        end

        it "can sign and verify after restoration" do
          pub_pem = key.to_pem
          priv_pem = key.private_to_pem
          restored = JWT::PQ::Key.from_pem_pair(public_pem: pub_pem, private_pem: priv_pem)

          message = "test message"
          sig = restored.sign(message)
          expect(restored.verify(message, sig)).to be true
        end

        it "raises on algorithm mismatch" do
          other_key = JWT::PQ::Key.generate(
            (JWT::PQ::MlDsa::ALGORITHMS.keys - [alg_name]).first
          )
          expect do
            JWT::PQ::Key.from_pem_pair(public_pem: key.to_pem, private_pem: other_key.private_to_pem)
          end.to raise_error(JWT::PQ::KeyError, /mismatch/)
        end
      end

      describe "JWT round-trip with PEM-restored keys" do
        let(:payload) { { "sub" => "42", "data" => "post-quantum" } }

        it "signs with original key, verifies with PEM-restored public key" do
          token = JWT.encode(payload, key, alg_name)
          restored = JWT::PQ::Key.from_pem(key.to_pem)

          decoded = JWT.decode(token, restored, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end

        it "signs with PEM-restored key, verifies with original" do
          restored = JWT::PQ::Key.from_pem_pair(
            public_pem: key.to_pem,
            private_pem: key.private_to_pem
          )
          token = JWT.encode(payload, restored, alg_name)

          decoded = JWT.decode(token, key, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end
      end
    end
  end
end
