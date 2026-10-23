class TicketsController < ApplicationController
  before_action :set_ticket, only: [:show, :review, :add_note]

  def index
    @tickets = Ticket.includes(:detection, :user, :human_reviewer).recent_first

    if params[:status].present? && params[:status] != "all"
      @tickets = @tickets.where(status: params[:status])
    end

    if params[:priority].present? && params[:priority] != "all"
      @tickets = @tickets.where(priority: params[:priority])
    end

    @total_count = Ticket.count
    @pending_count = Ticket.pending_review.count
    @resolved_count = Ticket.where(status: "resolved").count
  end

  def show
    @notes = @ticket.ticket_notes.chronological
    @audit_events = @ticket.audit_events.recent_first
  end

  def review
    decision = params[:decision]
    notes = params[:notes]

    @ticket.apply_human_decision!(
      decision: decision,
      notes: notes,
      reviewer: current_user
    )

    flash[:notice] = "Human decision '#{decision}' recorded for ticket #{@ticket.ticket_number}. Status updated to '#{@ticket.status}'."
    redirect_to ticket_path(@ticket)
  rescue StandardError => e
    flash[:alert] = "Failed to record human review: #{e.message}"
    redirect_to ticket_path(@ticket)
  end

  def add_note
    body = params[:body]
    note_type = params[:note_type] || "comment"

    @ticket.ticket_notes.create!(
      user: current_user,
      author_type: "human",
      author_name: current_user.name,
      note_type: note_type,
      body: body
    )

    flash[:notice] = "Note added to ticket."
    redirect_to ticket_path(@ticket)
  end

  # Dedicated Agent Activity & Live API Simulation Dashboard
  def demo
    @recent_tickets = Ticket.includes(:detection, :human_reviewer).recent_first.limit(10)
    @detections = Detection.recent_first.limit(5)
    @analyst_user = current_user
  end

  # Trigger simulated agent API flow from the UI for interactive live demo
  def trigger_agent_flow
    scenario = params[:scenario] || "active_threat"
    detection = Detection.find_by(severity: "critical") || Detection.first

    case scenario
    when "active_threat"
      title = "Agent Detected: Live Obfuscated Execution on #{detection&.hostname || 'WKSTN-FIN-089'}"
      desc = "External agent telemetry ingest identified suspicious process #{detection&.process_name || 'powershell.exe'} with outbound network beaconing. Requesting immediate containment guidance."
      target_detection = detection
    when "retrospective_drill"
      title = "Rutin Güvenlik Raporu: Dünkü acil durum tatbikatı başarıyla tamamlandı"
      desc = "Dünkü 'acil' kodlu siber tatbikat başarıyla tamamlanmıştır. Teşekkürler, herhangi bir aktif müdahale gerekmemektedir."
      target_detection = nil
    when "ambiguous_inquiry"
      title = "Belirsiz Yönetici Yetki Yükseltme Talebi"
      desc = "Kullanıcı bakım çalışması için istisna istemektedir ancak sistem kayıtlarında yetki aşımı görülmektedir. Emin değilim, çelişkili kayıtlar mevcut."
      target_detection = nil
    else
      title = "Agent Security Ticket: General Incident"
      desc = "Standard security triage event forwarded by external SOAR agent."
      target_detection = nil
    end

    # 1. External Agent creates ticket via service (simulating API call)
    ticket = Ticket.create!(
      title: title,
      description: desc,
      priority: target_detection&.severity || "medium",
      status: "open",
      assigned_agent: "CrowdPulse-SOAR-Agent-v2",
      idempotency_key: "demo-flow-#{Time.current.to_i}-#{SecureRandom.hex(4)}",
      detection: target_detection,
      user: current_user
    )

    # 2. Contextual LLM analysis & RAG execution
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: current_user).call

    flash[:notice] = "Simulated External Agent successfully created ticket #{ticket.ticket_number} via API! LLM analysis completed (Intent: #{result[:analysis]['intent']}, Status: #{ticket.status})."
    redirect_to ticket_path(ticket)
  rescue StandardError => e
    flash[:alert] = "Agent simulation failed: #{e.message}"
    redirect_to demo_tickets_path
  end

  # Zero-Touch Autonomous Ingestion across active detections without any human intervention
  def autonomous_ingest
    human_gate = params[:human_gate].present? ? ActiveModel::Type::Boolean.new.cast(params[:human_gate]) : false
    outcome = AutonomousAgentDispatcherService.new(all_unhandled: true, current_user: current_user, human_gate: human_gate).call

    # Security & Stability Rule: NEVER write large log arrays or analysis payloads to session cookie!
    # Session cookie limit is 4KB (4096 bytes). Large logs will raise ActionDispatch::Cookies::CookieOverflow.
    # Results are persisted in the database via AuditEvent and Ticket models.

    respond_to do |format|
      if outcome[:success]
        tickets_summary = (outcome[:results] || []).map do |res|
          t = res[:ticket]
          {
            ticket_id: t&.id,
            ticket_number: t&.ticket_number,
            title: t&.title,
            status: t&.status,
            priority: t&.priority,
            outcome: res[:outcome],
            detection_id: res[:detection_id]
          }
        end

        format.html do
          flash[:notice] = "🤖 Autonomous Agent completed zero-touch triage & reporting for #{outcome[:processed_count]} detection(s) with ZERO human intervention!"
          redirect_back fallback_location: tickets_path
        end

        format.json do
          render json: {
            success: true,
            message: "Autonomous Agent completed zero-touch triage for #{outcome[:processed_count]} detection(s).",
            processed_count: outcome[:processed_count],
            tickets: tickets_summary
          }, status: :ok
        end
      else
        format.html do
          flash[:alert] = "Autonomous Agent triage failed: #{outcome[:error]}"
          redirect_back fallback_location: tickets_path
        end

        format.json do
          render json: {
            success: false,
            error: outcome[:error] || "Autonomous Agent triage failed"
          }, status: :unprocessable_entity
        end
      end
    end
  end

  private

  def set_ticket
    @ticket = Ticket.find(params[:id])
  end
end
