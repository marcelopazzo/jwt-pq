# frozen_string_literal: true

require "net/http"

RSpec.describe JWT::PQ::JWKSet::Loader do
  let(:url) { "https://issuer.example/.well-known/jwks.json" }
  let(:key) { JWT::PQ::Key.generate(:ml_dsa_65) }
  let(:jwks_json) { JWT::PQ::JWKSet.new([key]).to_json }
  let(:loader) { described_class.new }

  def build_response(klass, code, message, body: nil, headers: {})
    resp = klass.new("1.1", code, message)
    resp.instance_variable_set(:@body, body) if body
    resp.instance_variable_set(:@read, true)
    headers.each { |k, v| resp[k] = v }
    if body
      resp.define_singleton_method(:read_body) do |&block|
        block ? block.call(body) : body
      end
    end
    resp
  end

  def ok(body:, headers: {})
    build_response(Net::HTTPOK, "200", "OK", body: body, headers: headers)
  end

  def not_modified
    build_response(Net::HTTPNotModified, "304", "Not Modified")
  end

  def redirect(location:)
    build_response(Net::HTTPFound, "302", "Found", headers: { "Location" => location })
  end

  def server_error
    build_response(Net::HTTPInternalServerError, "500", "Internal Server Error")
  end

  # Stub perform_request so it yields the response to the streaming
  # block, mirroring the real Net::HTTP block form.
  def stub_http(response)
    allow(loader).to receive(:perform_request).and_yield(response)
  end

  describe "#fetch on first hit" do
    before { stub_http(ok(body: jwks_json)) }

    it "returns a parsed JWKSet" do
      result = loader.fetch(url)
      expect(result).to be_a(JWT::PQ::JWKSet)
      expect(result.size).to eq(1)
    end

    it "looks up by kid using the original key's thumbprint" do
      result = loader.fetch(url)
      expect(result[key.jwk_thumbprint]).not_to be_nil
    end

    it "populates the cache" do
      loader.fetch(url)
      expect(loader.cached?(url)).to be(true)
    end

    it "sends no If-None-Match header on the first request" do
      loader.fetch(url)
      expect(loader).to have_received(:perform_request).with(anything, nil, anything, anything)
    end
  end

  describe "cache behaviour" do
    it "returns the cached set without hitting HTTP within the TTL" do
      stub_http(ok(body: jwks_json))
      first = loader.fetch(url, cache_ttl: 300)
      second = loader.fetch(url, cache_ttl: 300)
      expect(loader).to have_received(:perform_request).once
      expect(second).to equal(first)
    end

    it "re-fetches after the TTL expires, forwarding the stored ETag" do
      stub_http(ok(body: jwks_json, headers: { "ETag" => '"v1"' }))
      loader.fetch(url, cache_ttl: 0)
      loader.fetch(url, cache_ttl: 0)

      expect(loader).to have_received(:perform_request).with(anything, '"v1"', anything, anything)
    end

    it "reuses the cached JWKSet on a 304 Not Modified response" do
      stub_http(ok(body: jwks_json, headers: { "ETag" => '"v1"' }))
      first = loader.fetch(url, cache_ttl: 0)

      stub_http(not_modified)
      second = loader.fetch(url, cache_ttl: 0)

      expect(second).to equal(first)
    end

    it "#clear drops all cached entries" do
      stub_http(ok(body: jwks_json))
      loader.fetch(url)
      loader.clear
      expect(loader.cached?(url)).to be(false)
    end
  end

  describe "URL validation" do
    it "rejects non-HTTP schemes" do
      expect { loader.fetch("ftp://issuer.example/jwks.json") }
        .to raise_error(JWT::PQ::JWKSFetchError, /Invalid URL/)
    end

    it "rejects plain http:// by default" do
      expect { loader.fetch("http://issuer.example/jwks.json") }
        .to raise_error(JWT::PQ::JWKSFetchError, /non-HTTPS/)
    end

    it "allows plain http:// when allow_http: true" do
      stub_http(ok(body: jwks_json))
      expect { loader.fetch("http://issuer.example/jwks.json", allow_http: true) }
        .not_to raise_error
    end

    it "rejects a syntactically invalid URL" do
      expect { loader.fetch("not a url") }
        .to raise_error(JWT::PQ::JWKSFetchError, /Invalid URL/)
    end
  end

  describe "response handling" do
    it "refuses to follow redirects" do
      stub_http(redirect(location: "https://elsewhere.example/jwks.json"))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Refusing to follow redirect/)
    end

    it "raises on non-2xx responses" do
      stub_http(server_error)
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /HTTP 500/)
    end

    it "surfaces malformed JWKS bodies as KeyError" do
      stub_http(ok(body: '{"keys":"nope"}'))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::KeyError)
    end
  end

  describe "body size enforcement" do
    it "rejects a response whose Content-Length exceeds the cap" do
      stub_http(ok(body: jwks_json, headers: { "Content-Length" => "10000000" }))
      expect { loader.fetch(url, max_body_bytes: 1024) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Content-Length/)
    end

    it "rejects an oversized body even without Content-Length" do
      stub_http(ok(body: "x" * 2048))
      expect { loader.fetch(url, max_body_bytes: 1024) }
        .to raise_error(JWT::PQ::JWKSFetchError, /body too large/)
    end

    it "enforces the cap during streaming read when Content-Length is absent" do
      # Server without Content-Length delivers the body in chunks. The
      # cap must trip on the boundary chunk, before the full body is
      # buffered in memory. A post-read check would let all chunks be
      # allocated; this spec verifies the in-stream check fires and the
      # iterator never reaches chunks past the cap.
      response = build_response(Net::HTTPOK, "200", "OK")
      yielded = []

      response.define_singleton_method(:read_body) do |&block|
        4.times do |i|
          yielded << i
          block.call("x" * 400)
        end
      end
      allow(loader).to receive(:perform_request).and_yield(response)

      expect { loader.fetch(url, max_body_bytes: 1024) }
        .to raise_error(JWT::PQ::JWKSFetchError, /exceeded 1024 bytes during streaming read/)

      # Chunks 0, 1, 2 are consumed (800+400 > 1024 trips on chunk 2).
      # Chunk 3 must never be yielded.
      expect(yielded).to eq([0, 1, 2])
    end
  end

  describe "network errors" do
    it "wraps Net::OpenTimeout in JWKSFetchError" do
      allow(loader).to receive(:perform_request).and_raise(Net::OpenTimeout.new("connect timed out"))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Timeout/)
    end

    it "wraps Net::ReadTimeout in JWKSFetchError" do
      allow(loader).to receive(:perform_request).and_raise(Net::ReadTimeout.new("read timed out"))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Timeout/)
    end

    it "wraps SocketError in JWKSFetchError" do
      allow(loader).to receive(:perform_request).and_raise(SocketError.new("DNS failure"))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Network error/)
    end

    it "wraps Errno::ECONNREFUSED in JWKSFetchError" do
      allow(loader).to receive(:perform_request).and_raise(Errno::ECONNREFUSED)
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Network error/)
    end

    it "wraps OpenSSL::SSL::SSLError in JWKSFetchError" do
      allow(loader).to receive(:perform_request).and_raise(OpenSSL::SSL::SSLError.new("bad cert"))
      expect { loader.fetch(url) }
        .to raise_error(JWT::PQ::JWKSFetchError, /Network error/)
    end
  end

  describe ".default" do
    after { described_class.reset_default! }

    it "returns a process-global singleton" do
      expect(described_class.default).to equal(described_class.default)
    end

    it "reset_default! clears the singleton" do
      first = described_class.default
      described_class.reset_default!
      expect(described_class.default).not_to equal(first)
    end
  end

  describe "JWT::PQ::JWKSet.fetch" do
    after { described_class.reset_default! }

    it "delegates to the default loader" do
      allow(described_class.default).to receive(:fetch).with(url, cache_ttl: 60).and_return(:ok)
      expect(JWT::PQ::JWKSet.fetch(url, cache_ttl: 60)).to eq(:ok)
      expect(described_class.default).to have_received(:fetch).with(url, cache_ttl: 60)
    end
  end
end
