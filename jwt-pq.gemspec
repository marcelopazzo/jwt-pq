# frozen_string_literal: true

require_relative "lib/jwt/pq/version"

Gem::Specification.new do |spec|
  spec.name = "jwt-pq"
  spec.version = JWT::PQ::VERSION
  spec.authors = ["Marcelo Almeida"]
  spec.email = ["contact@marcelopazzo.com"]

  spec.summary = "Post-quantum JWT signatures (ML-DSA / FIPS 204) for Ruby"
  spec.description = "Adds ML-DSA-44, ML-DSA-65, and ML-DSA-87 post-quantum signature " \
                     "algorithms to the ruby-jwt ecosystem, with optional hybrid " \
                     "EdDSA + ML-DSA mode. Uses liboqs via FFI."
  spec.homepage = "https://github.com/marcelopazzo/jwt-pq"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "documentation_uri" => "https://rubydoc.info/gems/jwt-pq",
    "rubygems_mfa_required" => "true"
  }

  spec.requirements = ["cmake >= 3.15", "C compiler (gcc or clang)"]

  spec.post_install_message = <<~MSG
    jwt-pq compiles liboqs from source during installation.
    If the build failed, ensure cmake and a C compiler are installed.
    To use a system-installed liboqs instead:
      gem install jwt-pq -- --use-system-libraries
    For hybrid EdDSA+ML-DSA mode, add 'jwt-eddsa' to your Gemfile.
  MSG

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.start_with?("spec/", "vendor/", ".github/", "bench/") ||
        f.match?(/\A(?:\.git|\.rspec|\.rubocop|jwt-pq-plan)/)
    end
  end

  spec.extensions = ["ext/jwt/pq/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.15"
  spec.add_dependency "jwt", "~> 3.0"
  spec.add_dependency "pqc_asn1", "~> 0.1"
end
