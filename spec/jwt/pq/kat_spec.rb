# frozen_string_literal: true

require "json"

RSpec.describe "ML-DSA sigVer KATs (NIST ACVP)" do
  fixture_path = File.expand_path("../../fixtures/ml_dsa_acvp_sigver.json", __dir__)
  fixture = JSON.parse(File.read(fixture_path))

  fixture["groups"].each do |group|
    alg = group["parameterSet"]

    context "with #{alg} (interface=#{group["signatureInterface"]}, preHash=#{group["preHash"]})" do
      group["tests"].each do |tc|
        it "tcId=#{tc["tcId"]} verify returns #{tc["testPassed"]}" do
          pk_bytes = [tc["pk"]].pack("H*")
          sig_bytes = [tc["signature"]].pack("H*")
          msg_bytes = [tc["message"]].pack("H*")

          key = JWT::PQ::Key.from_public_key(alg, pk_bytes)
          expect(key.verify(msg_bytes, sig_bytes)).to eq(tc["testPassed"])
        end
      end
    end
  end
end
