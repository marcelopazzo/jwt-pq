#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate an ML-DSA-65 keypair with jwt-pq, export it as a JWK
# (draft-ietf-cose-dilithium / kty=AKP), sign a fixed message, and
# write jwk.json + msg + sig for Python to verify after parsing the JWK.

require "jwt/pq"
require "fileutils"
require "json"

out_dir = ARGV[0] || "interop_out"
FileUtils.mkdir_p(out_dir)

message = "jwt-pq cross-interop JWK test message"

key = JWT::PQ::Key.generate(:ml_dsa_65)
signature = key.sign(message)
jwk = JWT::PQ::JWK.new(key).export

File.write(File.join(out_dir, "jwk.json"), JSON.pretty_generate(jwk))
File.binwrite(File.join(out_dir, "jwk_msg.bin"), message)
File.binwrite(File.join(out_dir, "jwk_sig.bin"), signature)

puts "Ruby exported ML-DSA-65 JWK and signed #{message.bytesize}-byte message"
puts "  jwk kty=#{jwk[:kty]} alg=#{jwk[:alg]} pub=#{jwk[:pub].bytesize} chars kid=#{jwk[:kid]}"
puts "  sig: #{signature.bytesize} bytes"
puts "  out: #{out_dir}/"

raise "self-verify failed" unless key.verify(message, signature)

puts "Ruby self-verify: OK"
