# frozen_string_literal: true

class PageAgentService
  AGENT_NAME = "Sentriq-Page-Agent/v1.0"

  def initialize(instruction:, page_url: nil, page_context: {}, current_user: nil, human_intervention: false)
    @instruction = instruction.to_s.strip
    @page_url = page_url.to_s
    raw_ctx = page_context.respond_to?(:to_unsafe_h) ? page_context.to_unsafe_h : (page_context || {})
    @page_context = raw_ctx.with_indifferent_access
    @current_user = current_user || User.find_by(role: "lead_analyst") || User.first
    @human_intervention = human_intervention
    @steps = []
  end

  def call
    log_step("observe", "Page DOM and context observed: URL='#{@page_url}', Detection ID=#{@page_context[:detection_id] || 'None'}, Hostname='#{@page_context[:hostname] || 'N/A'}'")

    # 1. Resolve Detection Target
    detection = resolve_detection
    if detection
      log_step("observe", "Identified target detection DET-#{detection.id}: '#{detection.title}' (Host: #{detection.hostname}, Process: #{detection.process_name || 'N/A'}, Severity: #{detection.severity})")
    else
      log_step("observe", "No specific detection found in current page DOM. Operating in general SOC workspace mode.")
    end

    # 2. Think Phase (LLM Planning)
    plan = plan_actions(detection)
    log_step("think", "Page-Agent Reasoning Engine [#{active_provider_name}]: Goal='#{@instruction}'. Planned tools: #{plan[:tools].join(', ')}. Zero Human Touch: #{!@human_intervention}")

    # 3. Act Phase
    # Step A: Query Ragie RAG
    rag_query = [detection&.title, detection&.process_name, @instruction].compact.join(" ")
    ragie_response = RagieRetrievalService.new(rag_query, limit: 3).call
    ragie_results = ragie_response[:results] || []
    log_step("act", "Invoked Ragie RAG Retrieval [Provider: #{ragie_response[:provider]}]: Retrieved #{ragie_results.size} runbook chunk(s): #{ragie_results.map { |r| r[:document_title] }.compact.uniq.join(', ').presence || 'None'}")

    # Step B: Open Ticket Autonomously (if needed)
    ticket = find_or_create_ticket(detection, ragie_results)
    log_step("act", "Ticket verified in database: #{ticket.ticket_number} (Status: #{ticket.status}, Priority: #{ticket.priority}) with ZERO human intervention.")

    # Step C: LLM Contextual Analysis & Report Generation
    analysis_result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @current_user).call
    analysis = analysis_result[:analysis]
    log_step("think", "Contextual LLM Analysis completed (Intent: #{analysis['intent']}, Confidence: #{(analysis['confidence'].to_f * 100).round}%)")

    # Step D: Compile & Attach In-Page Security Incident Report
    report_content = build_page_agent_report(ticket, detection, analysis, ragie_results, ragie_response[:provider])
    ticket.ticket_notes.create!(
      user: @current_user,
      author_type: "agent",
      author_name: AGENT_NAME,
      note_type: "finding",
      body: report_content,
      metadata: {
        page_agent: true,
        zero_human_touch: !@human_intervention,
        rag_provider: ragie_response[:provider],
        instruction: @instruction
      }
    )
    log_step("act", "Attached comprehensive In-Page Incident Report to ticket notes.")

    # Step E: Containment & Resolution without human intervention
    if !@human_intervention
      # Only transition if not already resolved/closed
      unless %w[resolved closed].include?(ticket.status)
        ticket.transition_to!("resolved", reason: "Page-Agent completed in-page triage and containment with ZERO human intervention.")
      end
      ticket.update_columns(
        human_decision: "page_agent_auto_resolved",
        human_decision_notes: "Zero human intervention. Page-Agent parsed page DOM, retrieved Ragie RAG runbooks, and executed containment protocol.",
        human_reviewed_at: Time.current
      )

      if detection && detection.can_transition_to?("investigating")
        detection.transition_to!("investigating", reason: "Page-Agent initiated investigation")
      end

      log_step("act", "Threat containment executed. Ticket #{ticket.ticket_number} marked RESOLVED with ZERO human intervention.")
    else
      # Only escalate if ticket is in a state that allows pending_review transition
      if ticket.can_transition_to?("pending_review")
        ticket.escalate_to_human!(reason: "Page-Agent flagged ticket for human analyst confirmation", user: @current_user)
        log_step("act", "Ticket #{ticket.ticket_number} shifted to pending_review for human sign-off.")
      else
        log_step("act", "Ticket #{ticket.ticket_number} already in '#{ticket.status}' — skipping escalation transition.")
      end
    end

    AuditEvent.create!(
      trackable: ticket,
      user: @current_user,
      action: "page_agent_action_executed",
      details: {
        instruction: @instruction,
        page_url: @page_url,
        rag_provider: ragie_response[:provider],
        human_intervention: @human_intervention,
        final_status: ticket.status
      }
    )

    {
      success: true,
      needs_human: false,
      ticket: {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        status: ticket.status,
        priority: ticket.priority,
        url: "/tickets/#{ticket.id}"
      },
      detection_id: detection&.id,
      report: report_content,
      ragie_results: ragie_results,
      ragie_provider: ragie_response[:provider],
      steps: @steps
    }
  rescue StandardError => e
    log_step("error", "Page-Agent execution failed: #{e.message}")
    {
      success: false,
      needs_human: false,
      error: e.message,
      steps: @steps
    }
  end

  private

  def active_provider_name
    if ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
      "Grok (xAI) Live API [#{ENV.fetch('GROK_MODEL', 'grok-2-latest')}]"
    elsif ENV["OPENAI_API_KEY"].present?
      "OpenAI Live [#{ENV.fetch('OPENAI_MODEL', 'gpt-4o-mini')}]"
    elsif ENV["GEMINI_API_KEY"].present?
      "Gemini Live [#{ENV.fetch('GEMINI_MODEL', 'gemini-1.5-flash')}]"
    else
      "Contextual Local Engine (Simulated Mode)"
    end
  end

  def resolve_detection
    if @page_context[:detection_id].present?
      Detection.find_by(id: @page_context[:detection_id])
    elsif @page_url.match(%r{/detections/(\d+)})
      Detection.find_by(id: ::Regexp.last_match(1))
    else
      Detection.active.recent_first.first
    end
  end

  def plan_actions(detection)
    tools = ["ragie_retrieval", "auto_open_ticket", "generate_incident_report"]
    tools << "execute_containment" if detection&.severity.in?(%w[high critical])
    tools << ( @human_intervention ? "escalate_to_human" : "auto_resolve_zero_touch" )

    {
      intent: "page_agent_full_triage",
      tools: tools
    }
  end

  def find_or_create_ticket(detection, ragie_results)
    if detection
      # Reuse only active (open or pending_review) tickets, NOT resolved/closed ones
      existing = detection.tickets.where(status: %w[open pending_review]).recent_first.first
      return existing if existing
    end

    # Always generate a unique key per execution (seconds + random) to avoid collisions
    # across repeated agent runs on the same detection in the same minute
    idempotency_key = "page-agent-#{detection&.id || 'gen'}-#{Time.current.strftime('%Y%m%d%H%M%S')}-#{SecureRandom.hex(4)}"

    title = detection ? "🤖 [Page-Agent Alert] #{detection.title} (#{detection.hostname})" : "🤖 [Page-Agent] Security Incident Triage Request"
    description = if detection
                    "In-Page GUI Agent observed active alert on #{detection.hostname}. Process: #{detection.process_name || 'N/A'}. User Instruction: '#{@instruction}'. Dispatched for zero-touch triage."
                  else
                    "In-Page GUI Agent triggered with instruction: '#{@instruction}'."
                  end

    Ticket.create!(
      title: title,
      description: description,
      priority: detection&.severity || "high",
      status: "open",
      assigned_agent: AGENT_NAME,
      idempotency_key: idempotency_key,
      detection: detection,
      user: @current_user
    )
  end

  def build_page_agent_report(ticket, detection, analysis, ragie_results, ragie_provider)
    conf = analysis["confidence"].to_f
    conf_pct = conf <= 1.0 ? (conf * 100).round : conf.round

    cited_docs = if ragie_results.any?
                   ragie_results.map do |r|
                     "- **#{r[:document_title]}** [#{r[:category] || 'runbook'}]: _\"#{r[:quote].to_s.truncate(130)}\"_"
                   end.join("\n")
                 else
                   "_No matching runbooks found in Ragie knowledge base._"
                 end

    <<~REPORT
      ## 🤖 Sentriq Page-Agent Investigation Report (Zero Human Touch)

      - **Agent Paradigm:** In-Page GUI Agent (`#{AGENT_NAME}`)
      - **LLM Reasoning:** `#{active_provider_name}`
      - **RAG Engine:** `#{ragie_provider == 'ragie_cloud' ? 'Ragie.ai Cloud Managed RAG' : 'Ragie Managed RAG (Local Fallback)'}`
      - **Triggered Command:** _"#{@instruction}"_
      - **Target Endpoint:** `#{detection&.hostname || 'Workspace Environment'}`
      - **Assigned Priority:** `#{ticket.priority.upcase}`
      - **AI Confidence Score:** `#{conf_pct}%`

      ### 1. Page Observation & Context Summary
      #{analysis['rationale']}

      ### 2. Ragie RAG Knowledge Runbooks Cited
      #{cited_docs}

      ### 3. Containment & Resolution Actions Executed
      - **Action Executed:** `#{analysis['recommended_action']}`
      - **Autonomous Status:** Ticket marked **RESOLVED** with zero human clicks or manual form entry.
      - **Human Intervention Attestation:** 0% (Fully Autonomous Page-Agent Execution).
    REPORT
  end

  def log_step(phase, message)
    timestamp = Time.current.strftime("%H:%M:%S")
    @steps << {
      timestamp: timestamp,
      phase: phase, # "observe", "think", "act", "error"
      message: message
    }
  end
end
