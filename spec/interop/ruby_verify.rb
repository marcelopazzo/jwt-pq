#!/usr/bin/env ruby
# frozen_string_literal: true

# Verify an ML-DSA-65 signature produced by dilithium-py (Python) using jwt-pq.

require "jwt/pq"

in_dir = ARGV[0] || "interop_out"

pk  = File.binread(File.join(in_dir, "pk.bin"))
msg = File.binread(File.join(in_dir, "msg.bin"))
sig = File.binread(File.join(in_dir, "sig.bin"))

puts "Ruby verifying Python-produced ML-DSA-65 signature"
puts "  pk:  #{pk.bytesize} bytes"
puts "  msg: #{msg.bytesize} bytes"
puts "  sig: #{sig.bytesize} bytes"

key = JWT::PQ::Key.from_public_key(:ml_dsa_65, pk)

unless key.verify(msg, sig)
  puts "FAIL: jwt-pq rejected the signature"
  exit 1
end

puts "PASS: Ruby verified Python signature"
