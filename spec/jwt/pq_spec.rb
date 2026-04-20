# frozen_string_literal: true

RSpec.describe JWT::PQ do
  describe ".hybrid_available?" do
    it "returns true when ed25519 is available" do
      expect(described_class.hybrid_available?).to be true
    end

    it "returns false when ed25519 cannot be required" do
      allow(described_class).to receive(:require).with("ed25519").and_raise(LoadError)
      expect(described_class.hybrid_available?).to be false
    end
  end
end
