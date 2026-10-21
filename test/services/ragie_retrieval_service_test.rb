# frozen_string_literal: true

require "test_helper"

class RagieRetrievalServiceTest < ActiveSupport::TestCase
  setup do
    @doc = KnowledgeDocument.create!(
      title: "RB-0999: Advanced Persistent Threat Containment",
      category: "runbook",
      external_reference: "KB-APT-999",
      content: "When APT activity is confirmed, isolate host immediately from network. Kill malicious beaconing processes."
    )
  end

  test "retrieves runbooks via Ragie RAG engine with graceful fallback" do
    service = RagieRetrievalService.new("APT Containment isolate network", limit: 3)
    response = service.call

    assert response[:success]
    assert response[:matched]
    assert_includes %w[ragie_cloud ragie_local_fallback], response[:provider]
    assert response[:results].any?

    first_chunk = response[:results].first
    assert_not_nil first_chunk[:quote]
    assert_not_nil first_chunk[:document_title]
  end

  test "handles empty query gracefully" do
    service = RagieRetrievalService.new("", limit: 3)
    response = service.call

    assert response[:success]
    assert_not response[:matched]
    assert_empty response[:results]
  end
end
