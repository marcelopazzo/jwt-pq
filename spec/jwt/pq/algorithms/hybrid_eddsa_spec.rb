# frozen_string_literal: true

require "ed25519"

RSpec.describe JWT::PQ::Algorithms::HybridEdDsa do
  %w[ML-DSA-44 ML-DSA-65 ML-DSA-87].each do |ml_alg|
    context "with EdDSA+#{ml_alg}" do
      let(:hybrid_alg) { "EdDSA+#{ml_alg}" }
      let(:key) { JWT::PQ::HybridKey.generate(ml_alg.downcase.tr("-", "_").to_sym) }
      let(:payload) { { "sub" => "42", "name" => "PQ User", "iat" => 1_700_000_000 } }

      describe "JWT.encode / JWT.decode round-trip" do
        it "encodes and decodes a JWT" do
          token = JWT.encode(payload, key, hybrid_alg)
          decoded = JWT.decode(token, key, true, algorithms: [hybrid_alg])
          expect(decoded.first).to eq(payload)
        end

        it "sets the correct headers" do
          token = JWT.encode(payload, key, hybrid_alg)
          decoded = JWT.decode(token, key, true, algorithms: [hybrid_alg])
          header = decoded.last

          expect(header["alg"]).to eq(hybrid_alg)
          expect(header["pq_alg"]).to eq(ml_alg)
        end

        it "produces a token with concatenated signature" do
          token = JWT.encode(payload, key, hybrid_alg)
          parts = token.split(".")
          sig_bytes = Base64.urlsafe_decode64(parts[2])

          # Ed25519 sig (64 bytes) + ML-DSA sig
          expect(sig_bytes.bytesize).to be > 64
        end
      end

      describe "verification with verify-only key" do
        it "verifies using a HybridKey with only public keys" do
          token = JWT.encode(payload, key, hybrid_alg)

          verify_key = JWT::PQ::HybridKey.new(
            ed25519: key.ed25519_verify_key,
            ml_dsa: JWT::PQ::Key.from_public_key(ml_alg, key.ml_dsa_key.public_key)
          )

          decoded = JWT.decode(token, verify_key, true, algorithms: [hybrid_alg])
          expect(decoded.first).to eq(payload)
        end
      end

      describe "rejection of tampered tokens" do
        it "rejects a token signed with a different hybrid key" do
          token = JWT.encode(payload, key, hybrid_alg)
          other_key = JWT::PQ::HybridKey.generate(ml_alg.downcase.tr("-", "_").to_sym)

          expect do
            JWT.decode(token, other_key, true, algorithms: [hybrid_alg])
          end.to raise_error(JWT::VerificationError)
        end

        it "rejects a token with tampered Ed25519 signature" do
          token = JWT.encode(payload, key, hybrid_alg)
          parts = token.split(".")
          sig_bytes = Base64.urlsafe_decode64(parts[2])

          # Tamper the Ed25519 portion (first 64 bytes)
          tampered = sig_bytes.dup
          tampered.setbyte(0, (tampered.getbyte(0) + 1) % 256)
          parts[2] = Base64.urlsafe_encode64(tampered, padding: false)
          tampered_token = parts.join(".")

          expect do
            JWT.decode(tampered_token, key, true, algorithms: [hybrid_alg])
          end.to raise_error(JWT::VerificationError)
        end

        it "rejects a token with tampered ML-DSA signature" do
          token = JWT.encode(payload, key, hybrid_alg)
          parts = token.split(".")
          sig_bytes = Base64.urlsafe_decode64(parts[2])

          # Tamper the ML-DSA portion (after first 64 bytes)
          tampered = sig_bytes.dup
          tampered.setbyte(65, (tampered.getbyte(65) + 1) % 256)
          parts[2] = Base64.urlsafe_encode64(tampered, padding: false)
          tampered_token = parts.join(".")

          expect do
            JWT.decode(tampered_token, key, true, algorithms: [hybrid_alg])
          end.to raise_error(JWT::VerificationError)
        end
      end

      describe "error handling" do
        it "raises when signing with a verify-only key" do
          verify_key = JWT::PQ::HybridKey.new(
            ed25519: key.ed25519_verify_key,
            ml_dsa: JWT::PQ::Key.from_public_key(ml_alg, key.ml_dsa_key.public_key)
          )

          expect do
            JWT.encode(payload, verify_key, hybrid_alg)
          end.to raise_error(JWT::EncodeError)
        end

        it "raises when using a non-HybridKey for signing" do
          expect do
            JWT.encode(payload, "not a key", hybrid_alg)
          end.to raise_error(JWT::EncodeError, /HybridKey/)
        end
      end
    end
  end
end
