# frozen_string_literal: true

require "benchmark/ips"
require "jwt"
require "jwt/pq"
require "ed25519"

ALG = "EdDSA+ML-DSA-65"
PAYLOAD = { sub: "user-123", iat: 1_700_000_000, exp: 1_700_003_600 }.freeze
ML_DSA_FIXTURE = File.expand_path("fixtures/ml_dsa_65_sk.pem", __dir__)
ED_SEED_FIXTURE = File.expand_path("fixtures/ed25519_seed.bin", __dir__)

abort "Missing bench fixture: #{ML_DSA_FIXTURE}" unless File.exist?(ML_DSA_FIXTURE)
abort "Missing bench fixture: #{ED_SEED_FIXTURE}" unless File.exist?(ED_SEED_FIXTURE)

ml_key = JWT::PQ::Key.from_pem(File.read(ML_DSA_FIXTURE))
ed_key = Ed25519::SigningKey.new(File.binread(ED_SEED_FIXTURE))
hybrid = JWT::PQ::HybridKey.new(ed25519: ed_key, ml_dsa: ml_key)

TOKEN = JWT.encode(PAYLOAD, hybrid, ALG)

100.times { JWT.decode(TOKEN, hybrid, true, algorithms: [ALG], verify_expiration: false) }

report = Benchmark.ips(quiet: true) do |x|
  x.config(time: 5, warmup: 2)
  x.report("hybrid_verify") { JWT.decode(TOKEN, hybrid, true, algorithms: [ALG], verify_expiration: false) }
end

entry = report.entries.first
ips = entry.stats.central_tendency
us_per_op = 1_000_000.0 / ips

puts "METRIC algorithm=#{ALG}"
puts "METRIC verifies_per_sec=#{ips.round(2)}"
puts "METRIC us_per_verify=#{us_per_op.round(2)}"
