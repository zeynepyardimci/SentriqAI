require "net/http"
require "json"
require "uri"

class TicketContextualAnalyzerService
  def initialize(ticket:, current_user: nil)
    @ticket = ticket.is_a?(Ticket) ? ticket : Ticket.find(ticket)
    @current_user = current_user
  end

  def call
    # 1. RAG search over knowledge base runbooks via Ragie / Local RAG engine
    search_query = [@ticket.title, @ticket.description, @ticket.detection&.process_name].compact.join(" ")
    rag_response = RagieRetrievalService.new(search_query, limit: 3).call
    rag_results = rag_response[:results] || []

    payload = nil
    agent_mode = "simulated_local"

    if live_api_configured?
      begin
        payload = request_live_llm(rag_results)
        agent_mode = if grok_configured?
                       "grok_api"
                     elsif ENV["OPENAI_API_KEY"].present?
                       "openai_api"
                     else
                       "gemini_api"
                     end
      rescue StandardError => e
        Rails.logger.warn("[SentriqAI] External LLM ticket analysis failed (#{e.message}). Falling back to Contextual Analysis Engine.")
        payload = ContextualAnalysisEngine.analyze(@ticket, rag_results)
        agent_mode = "simulated_local"
      end
    else
      payload = ContextualAnalysisEngine.analyze(@ticket, rag_results)
      agent_mode = "simulated_local"
    end

    validated_payload = TicketAnalysisSchemaValidator.validate(payload)

    ActiveRecord::Base.transaction do
      @ticket.update!(
        llm_analysis: validated_payload,
        agent_mode: agent_mode,
        priority: validated_payload["priority"] || @ticket.priority
      )

      # Persist draft response as a ticket note
      @ticket.ticket_notes.create!(
        author_type: "agent",
        author_name: @ticket.assigned_agent.presence || "Sentriq AI Copilot",
        note_type: "analysis_draft",
        body: validated_payload["draft_response"],
        metadata: {
          intent: validated_payload["intent"],
          confidence: validated_payload["confidence"],
          requires_human_review: validated_payload["requires_human_review"],
          agent_mode: agent_mode
        }
      )

      # If the LLM determines human review is required, escalate ticket to pending_review
      if validated_payload["requires_human_review"] && @ticket.status != "pending_review"
        @ticket.escalate_to_human!(
          reason: "LLM contextual analysis flagged ticket for human review: #{validated_payload['rationale']}",
          user: @current_user
        )
      end

      AuditEvent.create!(
        trackable: @ticket,
        user: @current_user,
        action: "ticket_analyzed_by_ai",
        details: {
          intent: validated_payload["intent"],
          priority: validated_payload["priority"],
          requires_human_review: validated_payload["requires_human_review"],
          agent_mode: agent_mode
        }
      )
    end

    {
      success: true,
      ticket: @ticket,
      analysis: validated_payload,
      agent_mode: agent_mode
    }
  end

  private

  def live_api_configured?
    grok_configured? || ENV["OPENAI_API_KEY"].present? || ENV["GEMINI_API_KEY"].present?
  end

  def grok_configured?
    ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
  end

  def request_live_llm(rag_results)
    if grok_configured?
      request_grok(rag_results)
    elsif ENV["OPENAI_API_KEY"].present?
      request_openai(rag_results)
    elsif ENV["GEMINI_API_KEY"].present?
      request_gemini(rag_results)
    else
      raise "No LLM provider configured"
    end
  end

  def request_grok(rag_results)
    api_key = ENV["GROK_API_KEY"].presence || ENV["XAI_API_KEY"]
    model = ENV.fetch("GROK_MODEL", "grok-2-latest")
    uri = URI.parse("https://api.x.ai/v1/chat/completions")

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 30

    prompt = build_prompt(rag_results)

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Authorization"] = "Bearer #{api_key}"
    request["Content-Type"] = "application/json"
    request.body = {
      model: model,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: system_instruction },
        { role: "user", content: prompt }
      ],
      temperature: 0.1
    }.to_json

    response = http.request(request)
    raise "Grok (xAI) API returned HTTP #{response.code}: #{response.body}" unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    content = parsed.dig("choices", 0, "message", "content")
    JSON.parse(content)
  end

  def request_openai(rag_results)
    uri = URI.parse("https://api.openai.com/v1/chat/completions")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 25

    prompt = build_prompt(rag_results)

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Authorization"] = "Bearer #{ENV['OPENAI_API_KEY']}"
    request["Content-Type"] = "application/json"
    request.body = {
      model: ENV.fetch("OPENAI_MODEL", "gpt-4o-mini"),
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: system_instruction },
        { role: "user", content: prompt }
      ],
      temperature: 0.1
    }.to_json

    response = http.request(request)
    raise "OpenAI API error: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    content = parsed.dig("choices", 0, "message", "content")
    JSON.parse(content)
  end

  def request_gemini(rag_results)
    api_key = ENV["GEMINI_API_KEY"]
    model = ENV.fetch("GEMINI_MODEL", "gemini-1.5-flash")
    url = "https://generativelanguage.googleapis.com/v1beta/models/#{model}:generateContent?key=#{api_key}"
    uri = URI.parse(url)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 25

    prompt = build_prompt(rag_results)

    request = Net::HTTP::Post.new(uri.request_uri)
    request["Content-Type"] = "application/json"
    request.body = {
      contents: [{ role: "user", parts: [{ text: "#{system_instruction}\n\n#{prompt}" }] }],
      generationConfig: { responseMimeType: "application/json", temperature: 0.1 }
    }.to_json

    response = http.request(request)
    raise "Gemini API error: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    content = parsed.dig("candidates", 0, "content", "parts", 0, "text")
    JSON.parse(content)
  end

  def system_instruction
    <<~SYS
      You are Sentriq AI Contextual Decision Engine.
      Analyze the security ticket and associated telemetry.
      CRITICAL RULE: DO NOT rely on simple keyword matches like 'urgent', 'thanks', 'critical' or 'drill'.
      Evaluate the full context: is this a retrospective drill recap, a benign inquiry, or an active security threat?
      Output JSON strictly matching:
      {
        "intent": "string",
        "priority": "low|medium|high|critical",
        "recommended_action": "string",
        "draft_response": "string",
        "rationale": "string",
        "confidence": integer (0-100),
        "requires_human_review": boolean,
        "source_refs": [{"document_id": int, "quote": "string", "relevance_explanation": "string"}],
        "evidence_refs": [{"evidence_id": int, "description": "string"}]
      }
    SYS
  end

  def build_prompt(rag_results)
    evidence_text = if @ticket.detection
      @ticket.detection.evidences.map { |e| "- (#{e.evidence_type}): #{e.description}" }.join("\n")
    else
      "No direct detection attached."
    end

    rag_text = if rag_results.any?
      rag_results.map { |r| "<UNTRUSTED_DOCUMENT id='#{r[:document_id]}' title='#{r[:document_title]}'>\n#{r[:sanitized_content]}\n</UNTRUSTED_DOCUMENT>" }.join("\n")
    else
      "No matching runbook found in knowledge base."
    end

    <<~PROMPT
      === TICKET DETAILS ===
      Ticket Number: #{@ticket.ticket_number}
      Title: #{@ticket.title}
      Description: #{@ticket.description}
      Current Priority: #{@ticket.priority}

      === ASSOCIATED EVIDENCE ===
      #{evidence_text}

      === RETRIEVED KNOWLEDGE (UNTRUSTED RUNBOOK DATA) ===
      #{rag_text}

      Evaluate full context and return structured JSON.
    PROMPT
  end
end
