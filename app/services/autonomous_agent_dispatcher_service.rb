# frozen_string_literal: true

class AutonomousAgentDispatcherService
  AGENT_IDENTIFIER = "Sentriq-Autonomous-Agent/v2.1"

  def initialize(detection: nil, all_unhandled: false, current_user: nil)
    @detection = detection
    @all_unhandled = all_unhandled
    @current_user = current_user || User.find_by(role: "lead_analyst") || User.first
    @logs = []
  end

  def call
    targets = resolve_targets
    log "INFO", "Autonomous Dispatcher activated. Evaluating #{targets.size} detection(s) for zero-touch handling."

    results = targets.map do |detection|
      process_detection(detection)
    end

    {
      success: true,
      processed_count: results.size,
      results: results,
      logs: @logs
    }
  rescue StandardError => e
    log "ERROR", "Autonomous Dispatcher failure: #{e.message}"
    {
      success: false,
      error: e.message,
      logs: @logs
    }
  end

  private

  def resolve_targets
    if @detection.present?
      [@detection]
    elsif @all_unhandled
      # Find active detections that do not have active tickets
      active_ticket_detection_ids = Ticket.where.not(status: %w[resolved closed]).where.not(detection_id: nil).pluck(:detection_id)
      Detection.active.where.not(id: active_ticket_detection_ids).recent_first.limit(5)
    else
      # Default: pick first unhandled or first active detection
      active_ticket_detection_ids = Ticket.where.not(status: %w[resolved closed]).where.not(detection_id: nil).pluck(:detection_id)
      candidate = Detection.active.where.not(id: active_ticket_detection_ids).first || Detection.recent_first.first
      candidate ? [candidate] : []
    end
  end

  def process_detection(detection)
    log "SENSOR", "Incoming telemetry alert detected from endpoint: #{detection.hostname} (Process: #{detection.process_name || 'N/A'}, Severity: #{detection.severity})"

    # 1. Zero-Touch Autonomous Ticket Creation (No human clicks or form entry)
    idempotency_key = "auto-det-#{detection.id}-#{Time.current.strftime('%Y%m%d%H')}"
    existing_ticket = Ticket.find_by(idempotency_key: idempotency_key)

    if existing_ticket
      log "IDEMPOTENT", "Active autonomous ticket #{existing_ticket.ticket_number} already exists for detection ##{detection.id}. Skipping duplicate creation."
      return {
        ticket: existing_ticket,
        status: existing_ticket.status,
        action: "reused_existing",
        detection_id: detection.id
      }
    end

    telemetry_info = if detection.raw_telemetry.is_a?(Hash)
                       detection.raw_telemetry.slice('cmdline', 'parent_process', 'network').to_json
                     else
                       'Suspicious execution sequence'
                     end

    ticket = Ticket.create!(
      title: "🤖 [Zero-Touch Alert] #{detection.title} (#{detection.hostname})",
      description: "Autonomous EDR Sensor detected #{detection.process_name || 'suspicious activity'} on host #{detection.hostname}. Telemetry summary: #{telemetry_info}. Autonomous Agent dispatched for end-to-end triage with 0 human intervention.",
      priority: detection.severity,
      status: "open",
      assigned_agent: AGENT_IDENTIFIER,
      idempotency_key: idempotency_key,
      detection: detection,
      user: @current_user
    )

    log "AGENT", "Ticket #{ticket.ticket_number} autonomously opened in database with ZERO human intervention (Priority: #{ticket.priority})."

    # 2. Contextual LLM Triage & RAG Execution
    log "LLM", "Invoking Contextual Analysis Engine for ticket #{ticket.ticket_number} (Evaluating semantic intent, telemetry context, and RAG runbooks)..."
    analysis_result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @current_user).call
    analysis = analysis_result[:analysis]

    log "RAG", "RAG runbook search attached #{analysis['source_refs']&.size.to_i} verified document(s): #{analysis['source_refs']&.map { |s| s['document_title'] || s['title'] }&.compact_blank&.join(', ').presence || 'None'}."

    # 3. Autonomous Agent Research Note Attachment
    ticket.ticket_notes.create!(
      user: @current_user,
      author_type: "agent",
      author_name: AGENT_IDENTIFIER,
      note_type: "finding",
      body: "### 🤖 Autonomous Investigation Trace (Zero-Touch)\n\n" \
            "- **Intent:** #{analysis['intent']}\n" \
            "- **Confidence Score:** #{(analysis['confidence'].to_f * 100).round}%\n" \
            "- **Recommended Action:** #{analysis['recommended_action']}\n" \
            "- **Rationale:** #{analysis['rationale']}\n" \
            "- **Evidence References:** #{analysis['evidence_refs']&.join(', ').presence || 'Telemetry Logs'}\n" \
            "- **Tools Executed:** `edr_telemetry_fetcher`, `contextual_llm_triage`, `rag_runbook_retrieval`",
      metadata: {
        autonomous: true,
        confidence: analysis["confidence"],
        intent: analysis["intent"],
        source_refs: analysis["source_refs"]
      }
    )

    # 4. Decision & Routing: Autonomous Auto-Resolution vs Handover to Human
    outcome = nil
    if analysis["requires_human_review"] == true || ticket.priority.in?(%w[high critical])
      # High risk or destructive containment: Escalate to human review
      handover_reason = "Autonomous Agent detected high-risk or destructive operation (#{analysis['recommended_action']}). Autonomously transitioned to 'pending_review' for human confirmation."
      ticket.escalate_to_human!(reason: handover_reason, user: nil)
      log "HANDOVER", "High-risk action required. Autonomous Agent shifted #{ticket.ticket_number} to 'pending_review' with safety lock."
      outcome = "pending_review"
    else
      # Routine / drill / benign: Auto-resolve with zero human intervention
      ticket.transition_to!("resolved", reason: "Autonomously verified as routine/benign without human intervention.")
      ticket.update_columns(
        human_decision: "auto_resolved_by_agent",
        human_decision_notes: "Zero-touch autonomous verification completed.",
        human_reviewed_at: Time.current
      )
      log "AUTO-RESOLVED", "Ticket #{ticket.ticket_number} autonomously closed as verified benign/drill without human intervention."
      outcome = "resolved"
    end

    AuditEvent.create!(
      trackable: ticket,
      user: @current_user,
      action: "autonomous_agent_zero_touch_triage",
      details: {
        agent: AGENT_IDENTIFIER,
        detection_id: detection.id,
        outcome: outcome,
        intent: analysis["intent"],
        confidence: analysis["confidence"],
        requires_human_review: analysis["requires_human_review"]
      }
    )

    {
      ticket: ticket,
      status: ticket.status,
      outcome: outcome,
      analysis: analysis,
      detection_id: detection.id
    }
  end

  def log(stage, message)
    timestamp = Time.current.strftime("%H:%M:%S")
    @logs << "[#{timestamp}] [#{stage}] #{message}"
  end
end
