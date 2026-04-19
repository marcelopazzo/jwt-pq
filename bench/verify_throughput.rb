# frozen_string_literal: true

require "benchmark/ips"
require "jwt"
require "jwt/pq"

ALG = "ML-DSA-65"
PAYLOAD = { sub: "user-123", iat: 1_700_000_000, exp: 1_700_003_600 }.freeze
FIXTURE = File.expand_path("fixtures/ml_dsa_65_sk.pem", __dir__)

abort "Missing bench fixture: #{FIXTURE}" unless File.exist?(FIXTURE)
key = JWT::PQ::Key.from_pem(File.read(FIXTURE))
pub_key = JWT::PQ::Key.from_public_key(ALG, key.public_key)

TOKEN = JWT.encode(PAYLOAD, key, ALG)

100.times { JWT.decode(TOKEN, pub_key, true, algorithms: [ALG], verify_expiration: false) }

report = Benchmark.ips(quiet: true) do |x|
  x.config(time: 5, warmup: 2)
  x.report("verify") { JWT.decode(TOKEN, pub_key, true, algorithms: [ALG], verify_expiration: false) }
end

entry = report.entries.first
ips = entry.stats.central_tendency
us_per_op = 1_000_000.0 / ips

puts "METRIC verifies_per_sec=#{ips.round(2)}"
puts "METRIC us_per_verify=#{us_per_op.round(2)}"
