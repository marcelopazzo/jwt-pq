# frozen_string_literal: true

require "net/http"
require "uri"

module JWT
  module PQ
    class JWKSet
      # HTTP-backed JWKS loader with TTL cache and ETag revalidation.
      #
      # Fetches a remote JWKS document (e.g. `/.well-known/jwks.json`),
      # parses it via {JWT::PQ::JWKSet.import}, and caches the result
      # per-URL. Subsequent calls inside the TTL window return the cached
      # set without touching the network. Once the TTL expires, an
      # `If-None-Match` conditional GET is issued using the stored
      # `ETag`; a `304 Not Modified` response refreshes the cache
      # timestamp without re-parsing.
      #
      # Prefer the {JWT::PQ::JWKSet.fetch} shortcut over instantiating
      # this class directly — it uses a process-global loader so the
      # cache is shared across callers.
      #
      # Defense-in-depth defaults:
      #
      # - HTTPS only (pass `allow_http: true` to override for development).
      # - Redirects are rejected; update the URL to the canonical location.
      # - Response body is capped at 1 MB (`max_body_bytes`); ML-DSA public
      #   keys are ~1.3–2.6 KB each, so 1 MB already allows several hundred
      #   rotation candidates.
      # - Read/open timeouts default to 5 seconds.
      # - Failures raise {JWKSFetchError}; parse errors on the fetched body
      #   surface as {KeyError} from {JWKSet.import}.
      #
      # @example Fetch and verify a token
      #   jwks = JWT::PQ::JWKSet.fetch("https://issuer.example/.well-known/jwks.json")
      #   _payload, header = JWT.decode(token, nil, false)
      #   key = jwks[header["kid"]] or raise "unknown kid"
      #   payload, = JWT.decode(token, key, true, algorithms: [header["alg"]])
      class Loader
        DEFAULT_CACHE_TTL = 300
        DEFAULT_TIMEOUT = 5
        DEFAULT_OPEN_TIMEOUT = 5
        DEFAULT_MAX_BODY_BYTES = 1_048_576

        CacheEntry = Struct.new(:jwks, :etag, :fetched_at)
        private_constant :CacheEntry

        # @return [Loader] a process-global loader whose cache is shared
        #   across all {JWKSet.fetch} callers.
        def self.default
          @default ||= new
        end

        # Reset the process-global loader — mainly for tests.
        # @api private
        def self.reset_default!
          @default = nil
        end

        def initialize
          @cache = {}
          @mutex = Mutex.new
        end

        # Fetch the JWKS at `url`, honouring the cache if the entry is
        # still fresh.
        #
        # **URL provenance.** The URL is used verbatim: `Loader#fetch`
        # does not resolve DNS, inspect the target IP, or block private,
        # link-local, or cloud-metadata addresses. Callers are responsible
        # for ensuring the URL comes from a trusted source (e.g. a pinned
        # issuer configuration, not untrusted user input) to avoid SSRF.
        #
        # @param url [String] the absolute URL of the JWKS document.
        # @param cache_ttl [Integer] seconds the cached set is considered
        #   fresh. Default: 300.
        # @param timeout [Integer] read timeout in seconds. Default: 5.
        # @param open_timeout [Integer] connect timeout in seconds. Default: 5.
        # @param max_body_bytes [Integer] cap on response body size.
        #   Default: 1 MB.
        # @param allow_http [Boolean] allow plain `http://` URLs. Default:
        #   false (strongly recommended for production).
        # @param strict [Boolean] forwarded to {JWKSet.import}: if true,
        #   members with unknown `kty`/`alg` raise instead of being
        #   skipped. Default: false.
        # @return [JWKSet] the parsed set of verification keys.
        # @raise [JWKSFetchError] on network error, timeout, non-2xx
        #   response, oversized body, redirect, or non-HTTPS URL.
        # @raise [KeyError] if the fetched body is not a valid JWKS.
        def fetch(url, # rubocop:disable Metrics/ParameterLists
                  cache_ttl: DEFAULT_CACHE_TTL,
                  timeout: DEFAULT_TIMEOUT,
                  open_timeout: DEFAULT_OPEN_TIMEOUT,
                  max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                  allow_http: false,
                  strict: false)
          uri = validate_uri!(url, allow_http: allow_http)

          fresh = fresh_entry(url, cache_ttl)
          return fresh.jwks if fresh

          existing = @mutex.synchronize { @cache[url] }
          result = do_http_get(uri, existing&.etag, timeout, open_timeout, max_body_bytes)

          if result[:not_modified] && existing
            @mutex.synchronize { existing.fetched_at = now }
            existing.jwks
          else
            jwks = JWKSet.import(result[:body], strict: strict)
            @mutex.synchronize do
              @cache[url] = CacheEntry.new(jwks, result[:etag], now)
            end
            jwks
          end
        end

        # Drop all cached entries.
        # @return [void]
        def clear
          @mutex.synchronize { @cache.clear }
        end

        # @api private
        def cached?(url)
          @mutex.synchronize { @cache.key?(url) }
        end

        private

        def validate_uri!(url, allow_http:)
          uri = URI.parse(url)
          raise JWKSFetchError, "Invalid URL: #{url.inspect} (expected http/https)" unless uri.is_a?(URI::HTTP)

          if uri.scheme == "http" && !allow_http
            raise JWKSFetchError,
                  "Refusing non-HTTPS URL #{url.inspect} (pass allow_http: true to override)"
          end
          uri
        rescue URI::InvalidURIError => e
          raise JWKSFetchError, "Invalid URL: #{e.message}"
        end

        def fresh_entry(url, cache_ttl)
          @mutex.synchronize do
            entry = @cache[url]
            return nil unless entry
            return entry if (now - entry.fetched_at) < cache_ttl

            nil
          end
        end

        def do_http_get(uri, etag, timeout, open_timeout, max_body_bytes)
          result = nil
          perform_request(uri, etag, timeout, open_timeout) do |response|
            result = handle_response(response, max_body_bytes)
          end
          result
        rescue Net::OpenTimeout, Net::ReadTimeout => e
          raise JWKSFetchError, "Timeout fetching JWKS from #{uri}: #{e.message}"
        rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH,
               Errno::ENETUNREACH, OpenSSL::SSL::SSLError => e
          raise JWKSFetchError, "Network error fetching JWKS from #{uri}: #{e.message}"
        end

        # :nocov: — real HTTP path; unit tests stub this method.
        def perform_request(uri, etag, timeout, open_timeout, &)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == "https")
          http.read_timeout = timeout
          http.open_timeout = open_timeout

          req = Net::HTTP::Get.new(uri.request_uri)
          req["Accept"] = "application/jwk-set+json, application/json"
          req["If-None-Match"] = etag if etag

          http.request(req, &)
        end
        # :nocov:

        def handle_response(response, max_body_bytes)
          case response
          when Net::HTTPNotModified
            { not_modified: true }
          when Net::HTTPSuccess
            body = read_body_with_cap!(response, max_body_bytes)
            { not_modified: false, body: body, etag: response["ETag"] }
          when Net::HTTPRedirection
            raise JWKSFetchError,
                  "Refusing to follow redirect to #{response["Location"].inspect}"
          else
            raise JWKSFetchError, "HTTP #{response.code} #{response.message}"
          end
        end

        # Stream the response body into memory while enforcing the cap
        # on every chunk. A server that omits `Content-Length` cannot
        # force unbounded allocation: the accumulator is checked before
        # and after each append, and the connection is abandoned the
        # moment the cap is exceeded.
        def read_body_with_cap!(response, max_body_bytes)
          declared = response["Content-Length"]&.to_i
          if declared && declared > max_body_bytes
            raise JWKSFetchError,
                  "JWKS body too large: Content-Length #{declared} > #{max_body_bytes}"
          end

          buffer = String.new(capacity: declared || 0)
          response.read_body do |chunk|
            if buffer.bytesize + chunk.bytesize > max_body_bytes
              raise JWKSFetchError,
                    "JWKS body too large: exceeded #{max_body_bytes} bytes during streaming read"
            end
            buffer << chunk
          end
          buffer
        end

        def now
          Process.clock_gettime(Process::CLOCK_MONOTONIC).to_i
        end
      end
    end
  end
end
