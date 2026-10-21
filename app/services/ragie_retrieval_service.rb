# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

class RagieRetrievalService
  RAGIE_API_URL = "https://api.ragie.ai/retrievals"

  def initialize(query, limit: 5, partition: nil)
    @query = query.to_s.strip
    @limit = [[limit.to_i, 1].max, 10].min
    @partition = partition || ENV["RAGIE_PARTITION"].presence
  end

  def call
    return empty_result("Query is blank") if @query.blank?

    if ragie_configured?
      retrieve_from_ragie_cloud
    else
      retrieve_from_local_fallback
    end
  end

  def ragie_configured?
    ENV["RAGIE_API_KEY"].present?
  end

  private

  def retrieve_from_ragie_cloud
    uri = URI.parse(RAGIE_API_URL)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 20

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Authorization"] = "Bearer #{ENV['RAGIE_API_KEY']}"
    request["Content-Type"] = "application/json"

    body_params = {
      query: @query,
      top_k: @limit
    }
    body_params[:partition] = @partition if @partition.present?
    request.body = body_params.to_json

    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess)
      Rails.logger.warn("[Ragie RAG] Cloud API returned HTTP #{response.code}: #{response.body}. Falling back to local RAG.")
      return retrieve_from_local_fallback(fallback_reason: "Ragie API returned HTTP #{response.code}")
    end

    parsed = JSON.parse(response.body)
    scored_chunks = parsed["scored_chunks"] || []

    results = scored_chunks.map do |chunk|
      metadata = chunk["document_metadata"] || {}
      {
        chunk_id: chunk["id"] || chunk["chunk_id"],
        document_id: chunk["document_id"],
        document_title: metadata["title"] || chunk["document_name"] || "Ragie Runbook Document",
        category: metadata["category"] || "security_runbook",
        quote: chunk["text"] || chunk["content"],
        score: chunk["score"],
        provider: "ragie_cloud",
        sanitized_content: sanitize_chunk_for_prompt(chunk["text"] || chunk["content"])
      }
    end

    {
      success: true,
      matched: results.any?,
      provider: "ragie_cloud",
      results: results,
      message: "#{results.size} chunk(s) retrieved via Ragie.ai API"
    }
  rescue StandardError => e
    Rails.logger.warn("[Ragie RAG] Connection error: #{e.message}. Using local knowledge fallback.")
    retrieve_from_local_fallback(fallback_reason: "Ragie connection failed: #{e.message}")
  end

  def retrieve_from_local_fallback(fallback_reason: nil)
    local_search = SearchKnowledgeBaseService.new(@query, limit: @limit).call

    results = (local_search[:results] || []).map do |res|
      res.merge(
        provider: "ragie_local_fallback",
        ragie_note: fallback_reason || "Queried via Ragie Managed RAG Local Knowledge Engine"
      )
    end

    {
      success: true,
      matched: results.any?,
      provider: "ragie_local_fallback",
      results: results,
      message: local_search[:message] || "#{results.size} knowledge chunk(s) retrieved via Ragie engine fallback"
    }
  end

  def empty_result(msg)
    {
      success: true,
      matched: false,
      provider: ragie_configured? ? "ragie_cloud" : "ragie_local_fallback",
      results: [],
      message: msg
    }
  end

  def sanitize_chunk_for_prompt(text)
    sanitized = text.to_s.gsub("```", "'''")
    sanitized.gsub(/(ignore\s+all\s+previous\s+instructions|system\s+prompt|delete\s+all|override\s+rules)/i, "[DISARMED_UNTRUSTED_INSTRUCTION]")
  end
end
