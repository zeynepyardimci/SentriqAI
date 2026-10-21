class DetectionsController < ApplicationController
  before_action :set_detection, only: [:show, :investigate, :review, :add_note, :auto_ticket]

  def index
    @detections = SearchDetectionsService.new(params, current_user: current_user).call

    # Dashboard Metrics
    @total_count = Detection.count
    @at_risk_count = Detection.at_risk.count
    @critical_count = Detection.where(severity: "critical").count
    @solved_count = Detection.where(status: "solved").count
  end

  def show
    details = GetDetectionDetailsService.new(@detection.id, current_user: current_user).call
    @evidences = details[:evidences]
    @investigations = details[:investigations]
    @audit_events = details[:audit_events]
    @sla_status = details[:sla_status]
    @latest_investigation = @investigations.first
  end

  def investigate
    investigation = AiInvestigationAgentService.new(detection: @detection, user: current_user).call
    flash[:notice] = "AI Investigation Agent completed analysis (#{investigation.agent_mode == 'live_llm' ? 'Live LLM Provider' : 'Simulated Local Engine'}). Status updated to 'investigating'."
    redirect_to detection_path(@detection)
  rescue StandardError => e
    flash[:alert] = "Investigation failed: #{e.message}"
    redirect_to detection_path(@detection)
  end

  def review
    action = params[:review_action]
    note = params[:note_body]

    RequestHumanReviewService.new(
      detection: @detection,
      user: current_user,
      action: action,
      note_body: note
    ).call

    flash[:notice] = "Human review recorded successfully. Detection status updated to '#{@detection.reload.status}'."
    redirect_to detection_path(@detection)
  rescue StandardError => e
    flash[:alert] = "Review action failed: #{e.message}"
    redirect_to detection_path(@detection)
  end

  def add_note
    latest_investigation = @detection.investigations.recent_first.first
    if latest_investigation.nil?
      flash[:alert] = "No active investigation exists to attach a note to."
      redirect_to detection_path(@detection) and return
    end

    AddInvestigationNoteService.new(
      investigation: latest_investigation,
      user: current_user,
      note_type: params[:note_type] || "analyst_comment",
      body: params[:body]
    ).call

    flash[:notice] = "Analyst note added to investigation."
    redirect_to detection_path(@detection)
  rescue StandardError => e
    flash[:alert] = "Failed to add note: #{e.message}"
    redirect_to detection_path(@detection)
  end

  def auto_ticket
    outcome = AutonomousAgentDispatcherService.new(detection: @detection, current_user: current_user).call

    if outcome[:success] && outcome[:results].any?
      result = outcome[:results].first
      ticket = result[:ticket]
      flash[:notice] = "🤖 Autonomous Agent directly opened ticket #{ticket.ticket_number} without human intervention! (Status: #{ticket.status}, Intent: #{result[:analysis]&.dig('intent')})"
      redirect_to ticket_path(ticket)
    else
      flash[:alert] = "Autonomous Agent dispatch failed: #{outcome[:error] || 'No action taken'}"
      redirect_to detection_path(@detection)
    end
  end

  def check_sla
    result = SlaCheckerService.run!
    flash[:notice] = "SLA Check executed: #{result[:checked_count]} detections evaluated, #{result[:flagged_count]} flagged at risk."
    redirect_to detections_path
  end

  private

  def set_detection
    @detection = Detection.find(params[:id])
  end
end
