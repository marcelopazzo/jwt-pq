# frozen_string_literal: true

require "securerandom"

RSpec.describe "JWT::PQ::Key concurrency" do
  # Validates that per-instance mutex + eager FFI buffer init make
  # concurrent sign/verify/destroy! on a shared key race-free: there is
  # exactly one sk_buffer and one pk_buffer for the lifetime of the key,
  # and destroy! is serialized against in-flight sign/verify so no thread
  # can observe a half-destroyed buffer.
  describe "#sign under concurrent access" do
    let(:key) { JWT::PQ::Key.generate(:ml_dsa_65) }

    it "produces verifiable signatures from 8 parallel threads" do
      errors = []
      errors_mutex = Mutex.new

      threads = Array.new(8) do |i|
        Thread.new do
          message = "msg-#{i}-#{SecureRandom.hex(4)}"
          50.times do
            sig = key.sign(message)
            errors_mutex.synchronize { errors << "thread #{i} sig invalid" } unless key.verify(message, sig)
          end
        rescue StandardError => e
          errors_mutex.synchronize { errors << "thread #{i}: #{e.class}: #{e.message}" }
        end
      end

      threads.each(&:join)
      expect(errors).to be_empty
    end
  end

  describe "#sign after destroy! — TOCTOU guard" do
    # The per-instance mutex serializes destroy! against sign, so a
    # racing destroy! can only take effect between sign calls — never
    # in the middle of an FFI call where it would corrupt the in-flight
    # signature or segfault.
    it "raises KeyError when sk_buffer is nilled between calls" do
      key = JWT::PQ::Key.generate(:ml_dsa_65)
      key.destroy!

      expect { key.sign("data") }.to raise_error(JWT::PQ::KeyError, /Private key not available/)
    end

    it "serializes destroy! against in-flight sign/verify" do
      # 4 signer threads hammer the key while another thread destroys it.
      # Each sign must either complete and produce a verifiable signature
      # (happened-before destroy!) or raise KeyError (happened-after).
      # Any other outcome — a corrupted signature, a segfault, or a
      # ruby-level NoMethodError from a half-destroyed state — would
      # indicate the mutex is not actually serializing.
      key = JWT::PQ::Key.generate(:ml_dsa_65)
      pub_key = JWT::PQ::Key.from_public_key(:ml_dsa_65, key.public_key)

      results = Queue.new
      ready = Queue.new
      signers = Array.new(4) do
        Thread.new do
          msg = "msg-#{SecureRandom.hex(4)}"
          ready << :started
          100.times do
            results << [:ok, msg, key.sign(msg)]
          rescue JWT::PQ::KeyError
            results << [:destroyed]
            break
          end
        end
      end

      # Wait for every signer to have entered its loop before racing
      # destroy! — avoids the "sleep 0.001 hope it's enough" flake.
      4.times { ready.pop }
      key.destroy!
      signers.each(&:join)

      until results.empty?
        tag, msg, sig = results.pop
        case tag
        when :ok then expect(pub_key.verify(msg, sig)).to be true
        when :destroyed then next
        else raise "unexpected tag #{tag}"
        end
      end
    end
  end

  describe "#private_to_pem under concurrent destroy!" do
    # The PEM export reads @private_key and hands it to the DER builder.
    # Without the mutex, a racing destroy! could zero those bytes mid-build
    # and produce a corrupted PEM. The mutex guarantees any PEM that
    # returns is fully formed, and any destroy!-after-start path raises
    # KeyError on the next export attempt.
    it "never produces a corrupted PEM when racing destroy!" do
      10.times do
        key = JWT::PQ::Key.generate(:ml_dsa_65)
        pem_thread = Thread.new do
          key.private_to_pem
        rescue JWT::PQ::KeyError
          :destroyed
        end
        destroy_thread = Thread.new { key.destroy! }

        pem = pem_thread.value
        destroy_thread.join

        if pem.is_a?(String)
          expect(pem).to match(/\A-----BEGIN PRIVATE KEY-----/)
          expect(pem).to match(/-----END PRIVATE KEY-----\n?\z/)
          # A fully-formed PEM must round-trip to the same algorithm and
          # decode without an ASN.1 error — the strongest assertion that
          # no zero-bytes leaked into the middle of the private key.
          reimported = JWT::PQ::Key.from_pem(pem)
          expect(reimported.algorithm).to eq("ML-DSA-65")
        else
          expect(pem).to eq(:destroyed)
        end
      end
    end
  end

  describe "JWT::PQ::HybridKey concurrency" do
    before { skip "ed25519 gem not available" unless defined?(Ed25519) }

    # Hybrid sign is a compound operation (Ed25519 then ML-DSA). Without
    # a mutex on HybridKey, destroy! could run between the two component
    # signs, yielding a half-signed failure. With the mutex, either the
    # hybrid signature is fully formed or the entire call raises.
    it "serializes hybrid sign against destroy!" do
      key = JWT::PQ::HybridKey.generate(:ml_dsa_65)
      ed_verify_key = key.ed25519_verify_key
      ml_pub = JWT::PQ::Key.from_public_key(:ml_dsa_65, key.ml_dsa_key.public_key)

      results = Queue.new
      ready = Queue.new
      signers = Array.new(4) do
        Thread.new do
          msg = "msg-#{SecureRandom.hex(4)}"
          ready << :started
          50.times do
            sig = key.sign(msg)
            results << [:ok, msg, sig]
          rescue JWT::PQ::KeyError
            results << [:destroyed]
            break
          end
        end
      end

      4.times { ready.pop }
      key.destroy!
      signers.each(&:join)

      until results.empty?
        tag, msg, sig = results.pop
        case tag
        when :ok
          # Any returned signature must be fully formed and verifiable
          # on BOTH halves — the whole point of the mutex is that no
          # "half-signed" output can leak out of HybridKey#sign.
          ed_sig = sig.byteslice(0, 64)
          ml_sig = sig.byteslice(64..)
          expect { ed_verify_key.verify(ed_sig, msg) }.not_to raise_error
          expect(ml_pub.verify(msg, ml_sig)).to be true
        when :destroyed
          next
        else raise "unexpected tag #{tag}"
        end
      end
    end
  end

  describe "MlDsa.reset_handles!" do
    it "clears cached handles and the next call rebuilds them" do
      JWT::PQ::MlDsa.sign_handle("ML-DSA-65") # warm cache
      JWT::PQ::MlDsa.reset_handles!

      # Rebuild works
      expect(JWT::PQ::MlDsa.sign_handle("ML-DSA-65")).not_to be_null
    end

    it "is exposed at the public module level" do
      expect(JWT::PQ).to respond_to(:reset_handles!)
    end
  end
end
