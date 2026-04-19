# frozen_string_literal: true

require "benchmark/ips"
require "jwt"
require "jwt/pq"

ALG = "ML-DSA-65"
PAYLOAD = { sub: "user-123", iat: 1_700_000_000, exp: 1_700_003_600 }.freeze
FIXTURE = File.expand_path("fixtures/ml_dsa_65_sk.pem", __dir__)

abort "Missing bench fixture: #{FIXTURE}" unless File.exist?(FIXTURE)
key = JWT::PQ::Key.from_pem(File.read(FIXTURE))

100.times { JWT.encode(PAYLOAD, key, ALG) }

report = Benchmark.ips(quiet: true) do |x|
  x.config(time: 5, warmup: 2)
  x.report("sign") { JWT.encode(PAYLOAD, key, ALG) }
end

entry = report.entries.first
ips = entry.stats.central_tendency
us_per_op = 1_000_000.0 / ips

puts "METRIC sigs_per_sec=#{ips.round(2)}"
puts "METRIC us_per_sig=#{us_per_op.round(2)}"
