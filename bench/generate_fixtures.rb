# frozen_string_literal: true

# Regenerate bench fixture PEM keys. Idempotent — skips existing files.
# Keys are randomized (ML-DSA has no seed parameter in liboqs), so we
# generate once and persist to keep benchmark runs comparable over time.

require "jwt/pq"
require "fileutils"

FIXTURES = {
  ml_dsa_44: "ml_dsa_44_sk.pem",
  ml_dsa_65: "ml_dsa_65_sk.pem",
  ml_dsa_87: "ml_dsa_87_sk.pem"
}.freeze

out_dir = File.expand_path("fixtures", __dir__)
FileUtils.mkdir_p(out_dir)

FIXTURES.each do |alg, filename|
  path = File.join(out_dir, filename)
  if File.exist?(path)
    puts "skip  #{filename} (exists)"
    next
  end

  key = JWT::PQ::Key.generate(alg)
  File.write(path, key.private_to_pem)
  puts "wrote #{filename} (#{alg})"
end
