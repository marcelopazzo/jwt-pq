# frozen_string_literal: true

RSpec.describe JWT::PQ::Algorithms::MlDsa do
  %w[ML-DSA-44 ML-DSA-65 ML-DSA-87].each do |alg_name|
    context "with #{alg_name}" do
      let(:key) { JWT::PQ::Key.generate(alg_name) }
      let(:payload) { { "sub" => "1234567890", "name" => "Test User", "iat" => 1_516_239_022 } }

      describe "JWT.encode / JWT.decode round-trip" do
        it "encodes and decodes a JWT" do
          token = JWT.encode(payload, key, alg_name)

          expect(token).to be_a(String)
          expect(token.split(".").length).to eq(3)

          decoded = JWT.decode(token, key, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end

        it "sets the correct algorithm in the header" do
          token = JWT.encode(payload, key, alg_name)
          decoded = JWT.decode(token, key, true, algorithms: [alg_name])
          expect(decoded.last["alg"]).to eq(alg_name)
        end
      end

      describe "verification with public key only" do
        it "verifies using a public-key-only Key instance" do
          token = JWT.encode(payload, key, alg_name)
          pub_key = JWT::PQ::Key.from_public_key(alg_name, key.public_key)

          decoded = JWT.decode(token, pub_key, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end
      end

      describe "rejection of tampered tokens" do
        it "rejects a token with a different key" do
          token = JWT.encode(payload, key, alg_name)
          other_key = JWT::PQ::Key.generate(alg_name)

          expect do
            JWT.decode(token, other_key, true, algorithms: [alg_name])
          end.to raise_error(JWT::VerificationError)
        end
      end

      describe "error handling" do
        it "raises EncodeError when signing with a non-Key object" do
          expect do
            JWT.encode(payload, "not a key", alg_name)
          end.to raise_error(JWT::EncodeError, /JWT::PQ::Key/)
        end

        it "raises EncodeError when signing with a public-only key" do
          pub_key = JWT::PQ::Key.from_public_key(alg_name, key.public_key)
          expect do
            JWT.encode(payload, pub_key, alg_name)
          end.to raise_error(JWT::EncodeError, /Private key/)
        end

        it "raises DecodeError when verifying with a non-Key object" do
          token = JWT.encode(payload, key, alg_name)
          expect do
            JWT.decode(token, "not a key", true, algorithms: [alg_name])
          end.to raise_error(JWT::DecodeError)
        end
      end
    end
  end
end
