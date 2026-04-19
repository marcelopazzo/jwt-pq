# frozen_string_literal: true

require "benchmark/ips"
require "jwt"
require "jwt/pq"

ALG = ENV.fetch("ALG", "ML-DSA-65")
FIXTURES = {
  "ML-DSA-44" => "ml_dsa_44_sk.pem",
  "ML-DSA-65" => "ml_dsa_65_sk.pem",
  "ML-DSA-87" => "ml_dsa_87_sk.pem"
}.freeze

fixture_name = FIXTURES.fetch(ALG) { abort "Unknown ALG=#{ALG}. Expected one of: #{FIXTURES.keys.join(', ')}" }
fixture_path = File.expand_path("fixtures/#{fixture_name}", __dir__)

PAYLOAD = { sub: "user-123", iat: 1_700_000_000, exp: 1_700_003_600 }.freeze

abort "Missing bench fixture: #{fixture_path}" unless File.exist?(fixture_path)
key = JWT::PQ::Key.from_pem(File.read(fixture_path))

100.times { JWT.encode(PAYLOAD, key, ALG) }

report = Benchmark.ips(quiet: true) do |x|
  x.config(time: 5, warmup: 2)
  x.report("sign") { JWT.encode(PAYLOAD, key, ALG) }
end

entry = report.entries.first
ips = entry.stats.central_tendency
us_per_op = 1_000_000.0 / ips

puts "METRIC algorithm=#{ALG}"
puts "METRIC sigs_per_sec=#{ips.round(2)}"
puts "METRIC us_per_sig=#{us_per_op.round(2)}"
