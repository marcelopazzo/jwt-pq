#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate an ML-DSA-65 keypair with jwt-pq, sign a fixed message,
# and write raw pk/msg/sig bytes to disk for Python to verify.

require "jwt/pq"
require "fileutils"

out_dir = ARGV[0] || "interop_out"
FileUtils.mkdir_p(out_dir)

message = "jwt-pq cross-interop test message"

key = JWT::PQ::Key.generate(:ml_dsa_65)
signature = key.sign(message)

File.binwrite(File.join(out_dir, "pk.bin"), key.public_key)
File.binwrite(File.join(out_dir, "msg.bin"), message)
File.binwrite(File.join(out_dir, "sig.bin"), signature)

puts "Ruby signed #{message.bytesize}-byte message with ML-DSA-65"
puts "  pk:  #{key.public_key.bytesize} bytes"
puts "  sig: #{signature.bytesize} bytes"
puts "  out: #{out_dir}/"

raise "self-verify failed" unless key.verify(message, signature)

puts "Ruby self-verify: OK"
