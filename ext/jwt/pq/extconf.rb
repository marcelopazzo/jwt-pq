# frozen_string_literal: true

require "mkmf"
require "fileutils"
require "open-uri"
require "digest"
require "rubygems/package"
require "zlib"
require "etc"
require "tmpdir"

LIBOQS_VERSION = "0.15.0"
LIBOQS_SHA256 = "3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c"
LIBOQS_URL = "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/#{LIBOQS_VERSION}.tar.gz"

PACKAGE_ROOT_DIR = File.expand_path("../../..", __dir__)
VENDOR_DIR = File.join(PACKAGE_ROOT_DIR, "lib", "jwt", "pq", "vendor")

def write_dummy_makefile
  File.write("Makefile", <<~MAKEFILE)
    all:
    \t@echo "jwt-pq: nothing to compile"
    install:
    \t@echo "jwt-pq: nothing to install"
    clean:
    \t@echo "jwt-pq: nothing to clean"
  MAKEFILE
end

def use_system_libraries?
  ENV.key?("JWT_PQ_USE_SYSTEM_LIBRARIES") ||
    enable_config("system-libraries", false)
end

def check_cmake!
  cmake = find_executable("cmake")
  unless cmake
    abort <<~MSG
      ERROR: cmake is required to compile liboqs for jwt-pq.

      Install it with:
        macOS:  brew install cmake
        Ubuntu: sudo apt-get install cmake

      Alternatively, install liboqs manually and use:
        gem install jwt-pq -- --use-system-libraries
    MSG
  end
  cmake
end

def download_source(dest_dir)
  tarball_path = File.join(dest_dir, "liboqs-#{LIBOQS_VERSION}.tar.gz")

  # Support local tarball via env var (for air-gapped environments)
  source = ENV.fetch("JWT_PQ_LIBOQS_SOURCE", LIBOQS_URL)

  $stdout.puts "jwt-pq: downloading liboqs #{LIBOQS_VERSION}..."
  if source.start_with?("http")
    URI.open(source) do |remote| # rubocop:disable Security/Open
      File.binwrite(tarball_path, remote.read)
    end
  else
    FileUtils.cp(source, tarball_path)
  end

  # Verify checksum
  actual = Digest::SHA256.file(tarball_path).hexdigest
  unless actual == LIBOQS_SHA256
    abort "ERROR: SHA-256 mismatch for liboqs tarball.\n" \
          "  Expected: #{LIBOQS_SHA256}\n" \
          "  Got:      #{actual}"
  end

  tarball_path
end

def extract_tarball(tarball_path, dest_dir)
  $stdout.puts "jwt-pq: extracting liboqs #{LIBOQS_VERSION}..."
  File.open(tarball_path, "rb") do |file|
    Zlib::GzipReader.wrap(file) do |gz|
      Gem::Package::TarReader.new(gz) do |tar|
        tar.each do |entry|
          dest = File.join(dest_dir, entry.full_name)
          if entry.directory?
            FileUtils.mkdir_p(dest)
          elsif entry.file?
            FileUtils.mkdir_p(File.dirname(dest))
            File.binwrite(dest, entry.read)
            File.chmod(entry.header.mode, dest) if entry.header.mode
          end
        end
      end
    end
  end

  File.join(dest_dir, "liboqs-#{LIBOQS_VERSION}")
end

def build_liboqs(source_dir)
  build_dir = File.join(source_dir, "build")
  FileUtils.mkdir_p(build_dir)
  FileUtils.mkdir_p(VENDOR_DIR)

  nproc = begin
    Etc.nprocessors
  rescue StandardError
    2
  end

  cmake_args = %W[
    -DBUILD_SHARED_LIBS=ON
    -DOQS_MINIMAL_BUILD=SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87
    -DOQS_BUILD_ONLY_LIB=ON
    -DOQS_USE_OPENSSL=OFF
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX=#{VENDOR_DIR}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  ]

  # Use Ninja if available (faster), fall back to Make
  if find_executable("ninja")
    cmake_args << "-GNinja"
  end

  $stdout.puts "jwt-pq: configuring liboqs #{LIBOQS_VERSION} (ML-DSA only)..."
  unless system("cmake", "-S", source_dir, "-B", build_dir, *cmake_args)
    abort "ERROR: cmake configure failed for liboqs"
  end

  $stdout.puts "jwt-pq: compiling liboqs (using #{nproc} cores)..."
  unless system("cmake", "--build", build_dir, "--parallel", nproc.to_s)
    abort "ERROR: cmake build failed for liboqs"
  end

  $stdout.puts "jwt-pq: installing liboqs to vendor directory..."
  unless system("cmake", "--install", build_dir)
    abort "ERROR: cmake install failed for liboqs"
  end
end

def find_vendored_library
  %w[dylib so].each do |ext|
    path = File.join(VENDOR_DIR, "lib", "liboqs.#{ext}")
    return path if File.exist?(path)
  end
  nil
end

# --- Main ---

if use_system_libraries?
  $stdout.puts "jwt-pq: using system liboqs (--use-system-libraries)"
  write_dummy_makefile
  exit 0
end

check_cmake!

Dir.mktmpdir("jwt-pq-build") do |tmp_dir|
  tarball = download_source(tmp_dir)
  source_dir = extract_tarball(tarball, tmp_dir)
  build_liboqs(source_dir)
end

lib_path = find_vendored_library
if lib_path
  $stdout.puts "jwt-pq: liboqs #{LIBOQS_VERSION} installed at #{lib_path}"
else
  abort "ERROR: liboqs shared library not found after build"
end

write_dummy_makefile
