#!/usr/bin/env ruby
# frozen_string_literal: true

require "jwt/pq"

puts "jwt-pq v#{JWT::PQ::VERSION} smoke test"

# ML-DSA-65 sign/verify round-trip
key = JWT::PQ::Key.generate(:ml_dsa_65)
token = JWT.encode({ "sub" => "smoke-test" }, key, "ML-DSA-65")
decoded = JWT.decode(token, key, true, algorithms: ["ML-DSA-65"])

raise "Decode failed" unless decoded.first["sub"] == "smoke-test"

puts "ML-DSA-65 sign/verify: OK"

# PEM round-trip
pub_pem = key.to_pem
restored = JWT::PQ::Key.from_pem(pub_pem)
decoded = JWT.decode(token, restored, true, algorithms: ["ML-DSA-65"])

raise "PEM round-trip failed" unless decoded.first["sub"] == "smoke-test"

puts "PEM round-trip: OK"

# JWK round-trip
jwk = JWT::PQ::JWK.new(key)
imported = JWT::PQ::JWK.import(jwk.export)
decoded = JWT.decode(token, imported, true, algorithms: ["ML-DSA-65"])

raise "JWK round-trip failed" unless decoded.first["sub"] == "smoke-test"

puts "JWK round-trip: OK"

# Key destroy
key.destroy!
raise "destroy! failed" if key.private?

puts "Key#destroy!: OK"
puts "All smoke tests passed"
