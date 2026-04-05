# frozen_string_literal: true

RSpec.describe JWT::PQ do
  describe ".hybrid_available?" do
    it "returns true when ed25519 is available" do
      expect(described_class.hybrid_available?).to be true
    end
  end
end
