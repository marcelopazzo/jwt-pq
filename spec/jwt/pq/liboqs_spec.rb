# frozen_string_literal: true

RSpec.describe JWT::PQ::LibOQS do
  describe ".lib_path" do
    around do |example|
      original = ENV.delete("OQS_LIB")
      example.run
    ensure
      ENV["OQS_LIB"] = original if original
    end

    it "returns OQS_LIB when set" do
      ENV["OQS_LIB"] = "/custom/liboqs.dylib"
      expect(described_class.lib_path).to eq("/custom/liboqs.dylib")
    end

    it "returns the vendored path when present" do
      allow(described_class).to receive(:vendored_lib_path).and_return("/vendored/liboqs.dylib")
      expect(described_class.lib_path).to eq("/vendored/liboqs.dylib")
    end

    it "falls back to the system library name" do
      allow(described_class).to receive(:vendored_lib_path).and_return(nil)
      expect(described_class.lib_path).to eq("oqs")
    end
  end

  describe ".vendored_lib_path" do
    it "returns nil when no vendored library exists" do
      allow(File).to receive(:exist?).and_return(false)
      expect(described_class.send(:vendored_lib_path)).to be_nil
    end

    it "returns the dylib path when present" do
      allow(File).to receive(:exist?) do |path|
        path.end_with?("liboqs.dylib")
      end
      expect(described_class.send(:vendored_lib_path)).to end_with("liboqs.dylib")
    end
  end
end
