# frozen_string_literal: true

require "json"
require "openssl"
require "base64"

RSpec.describe JWT::PQ::JWK do
  JWT::PQ::MlDsa::ALGORITHMS.each_key do |alg_name|
    context "with #{alg_name}" do
      let(:key) { JWT::PQ::Key.generate(alg_name) }
      let(:jwk) { described_class.new(key) }

      describe "#export" do
        it "exports public-only JWK by default" do
          exported = jwk.export
          expect(exported[:kty]).to eq("AKP")
          expect(exported[:alg]).to eq(alg_name)
          expect(exported[:pub]).to be_a(String)
          expect(exported[:kid]).to be_a(String)
          expect(exported).not_to have_key(:priv)
        end

        it "exports JWK with private key when requested" do
          exported = jwk.export(include_private: true)
          expect(exported[:priv]).to be_a(String)
        end

        it "does not include private key when not available" do
          pub_key = JWT::PQ::Key.from_public_key(alg_name, key.public_key)
          pub_jwk = described_class.new(pub_key)
          exported = pub_jwk.export(include_private: true)
          expect(exported).not_to have_key(:priv)
        end
      end

      describe ".import" do
        it "round-trips a public-only JWK" do
          exported = jwk.export
          restored = described_class.import(exported)

          expect(restored.algorithm).to eq(alg_name)
          expect(restored.public_key).to eq(key.public_key)
          expect(restored).not_to be_private
        end

        it "round-trips a JWK with private key" do
          exported = jwk.export(include_private: true)
          restored = described_class.import(exported)

          expect(restored.algorithm).to eq(alg_name)
          expect(restored.public_key).to eq(key.public_key)
          expect(restored.private_key).to eq(key.private_key)
          expect(restored).to be_private
        end

        it "accepts string keys" do
          exported = jwk.export.transform_keys(&:to_s)
          restored = described_class.import(exported)
          expect(restored.public_key).to eq(key.public_key)
        end
      end

      describe "#thumbprint" do
        it "produces a deterministic thumbprint" do
          t1 = jwk.thumbprint
          t2 = described_class.new(key).thumbprint
          expect(t1).to eq(t2)
        end

        it "produces different thumbprints for different keys" do
          other_key = JWT::PQ::Key.generate(alg_name)
          other_jwk = described_class.new(other_key)
          expect(jwk.thumbprint).not_to eq(other_jwk.thumbprint)
        end

        it "is used as kid in export" do
          exported = jwk.export
          expect(exported[:kid]).to eq(jwk.thumbprint)
        end

        # Independent RFC 7638 thumbprint calculation, following the AKP
        # required-members list from draft-ietf-cose-dilithium: alg, kty, pub.
        # Any divergence here (field order, field name, JSON canonicalization,
        # hash, encoding) would break interop with other AKP implementations.
        it "matches an independent RFC 7638 computation over (alg, kty, pub)" do
          pub_b64 = Base64.urlsafe_encode64(key.public_key, padding: false)
          canonical = JSON.generate("alg" => alg_name, "kty" => "AKP", "pub" => pub_b64)
          expected_digest = OpenSSL::Digest::SHA256.digest(canonical)
          expected = Base64.urlsafe_encode64(expected_digest, padding: false)

          expect(jwk.thumbprint).to eq(expected)
        end
      end

      describe "JWT round-trip with JWK-restored keys" do
        let(:payload) { { "sub" => "jwk-test", "iat" => 1_700_000_000 } }

        it "signs with original, verifies with JWK-imported key" do
          token = JWT.encode(payload, key, alg_name)
          restored = described_class.import(jwk.export)

          decoded = JWT.decode(token, restored, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end

        it "signs with JWK-imported key, verifies with original" do
          full_jwk = jwk.export(include_private: true)
          restored = described_class.import(full_jwk)
          token = JWT.encode(payload, restored, alg_name)

          decoded = JWT.decode(token, key, true, algorithms: [alg_name])
          expect(decoded.first).to eq(payload)
        end
      end
    end
  end

  describe "validation" do
    it "raises for missing kty" do
      expect { described_class.import({ "alg" => "ML-DSA-44", "pub" => "abc" }) }
        .to raise_error(JWT::PQ::KeyError, /kty/)
    end

    it "raises for wrong kty" do
      expect { described_class.import({ "kty" => "RSA", "alg" => "ML-DSA-44", "pub" => "abc" }) }
        .to raise_error(JWT::PQ::KeyError, /kty/)
    end

    it "raises for missing alg" do
      expect { described_class.import({ "kty" => "AKP", "pub" => "abc" }) }
        .to raise_error(JWT::PQ::KeyError, /alg/)
    end

    it "raises for unsupported alg" do
      expect { described_class.import({ "kty" => "AKP", "alg" => "FAKE", "pub" => "abc" }) }
        .to raise_error(JWT::PQ::KeyError, /Unsupported/)
    end

    it "raises for non-Key input" do
      expect { described_class.new("not a key") }
        .to raise_error(JWT::PQ::KeyError, /JWT::PQ::Key/)
    end

    it "raises for missing pub field" do
      expect { described_class.import({ "kty" => "AKP", "alg" => "ML-DSA-44" }) }
        .to raise_error(JWT::PQ::KeyError, /pub/)
    end

    it "raises for invalid base64url in pub" do
      expect { described_class.import({ "kty" => "AKP", "alg" => "ML-DSA-44", "pub" => "!!!invalid!!!" }) }
        .to raise_error(JWT::PQ::KeyError, /base64url.*pub/i)
    end

    it "raises for invalid base64url in priv" do
      key = JWT::PQ::Key.generate(:ml_dsa_44)
      jwk = described_class.new(key).export
      jwk[:priv] = "!!!invalid!!!"
      expect { described_class.import(jwk) }
        .to raise_error(JWT::PQ::KeyError, /base64url.*priv/i)
    end
  end
end
