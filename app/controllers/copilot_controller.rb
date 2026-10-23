# frozen_string_literal: true

class CopilotController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:chat, :autonomous_triage, :load_scenario]
  before_action :set_event_context, only: [:index, :investigation_data]

  def index
    @detections = Detection.recent_first.limit(15)
    @deep_analysis = DeepInvestigationService.new(
      detection: @detection,
      ticket: @ticket,
      current_user: current_user
    ).call

    @messages = if @detection || @ticket
                  CopilotMessage.where(detection_id: @detection&.id)
                                .or(CopilotMessage.where(ticket_id: @ticket&.id))
                                .chronological.limit(50)
                else
                  CopilotMessage.none
                end
  end

  def chat
    query = params[:query].to_s.strip
    return render json: { success: false, error: "Query cannot be empty" }, status: :bad_request if query.blank?

    result = AvatarConversationService.new(
      query: query,
      detection_id: params[:detection_id],
      ticket_id: params[:ticket_id],
      current_user: current_user
    ).call

    render json: result
  rescue StandardError => e
    render json: { success: false, error: e.message }, status: :internal_server_error
  end

  def autonomous_triage
    detection = Detection.find_by(id: params[:detection_id])
    return render json: { success: false, error: "Detection not found" }, status: :not_found unless detection

    dispatcher_result = AutonomousAgentDispatcherService.new(
      detection: detection,
      human_gate: true,
      current_user: current_user
    ).call

    target_ticket = detection.tickets.recent_first.first
    deep_analysis = DeepInvestigationService.new(
      detection: detection,
      ticket: target_ticket,
      current_user: current_user
    ).call

    # Prepare speech announcement for the avatar
    speech_announcement = if target_ticket
                            "Otonom triyaj tamamlandı. Bilet oluşturuldu: #{target_ticket.ticket_number}. Öncelik #{target_ticket.priority.upcase}, durum #{target_ticket.status}."
                          else
                            "Otonom triyaj tamamlandı. Güvenlik analizi tamamlandı."
                          end

    # Record system message in chat
    CopilotMessage.create!(
      detection: detection,
      ticket: target_ticket,
      user: current_user,
      role: "system",
      content: "🤖 Otonom Ajan Triyajı Tamamladı: Bilet #{target_ticket&.ticket_number || 'Açıldı'}, Durum: #{target_ticket&.status} (İnsan Onayı Bekleniyor)."
    )

    render json: {
      success: true,
      logs: dispatcher_result[:logs],
      ticket: target_ticket ? serialize_ticket(target_ticket) : nil,
      speech_text: speech_announcement,
      deep_analysis: deep_analysis
    }
  rescue StandardError => e
    render json: { success: false, error: e.message }, status: :internal_server_error
  end

  def investigation_data
    deep_analysis = DeepInvestigationService.new(
      detection: @detection,
      ticket: @ticket,
      current_user: current_user
    ).call

    render json: deep_analysis
  end

  def load_scenario
    scenario = params[:scenario].to_s

    detection = case scenario
                when "scenario_a"
                  # Scenario A: Low risk / routine / potential false positive
                  Detection.find_or_create_by!(
                    title: "Dünkü Rutin Yedekleme ve Arşiv Tatbikatı Kontrolü",
                    hostname: "SRV-BACKUP-02"
                  ) do |d|
                    d.description = "Zamanlanmış acil durum tatbikatı tamamlandı. Rutin PowerShell arşivleme betiği çalıştırıldı."
                    d.severity = "low"
                    d.status = "open"
                    d.process_name = "powershell.exe"
                    d.process_id = 1840
                    d.parent_process_name = "taskeng.exe"
                    d.command_line = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup_drill.ps1"
                    d.triggered_at = 15.minutes.ago
                  end
                else
                  # Scenario B: Critical PowerShell LOLBin / Ransomware precursor
                  Detection.find_or_create_by!(
                    title: "Volume Shadow Copy Deletion & Encoded PowerShell Ingress",
                    hostname: "WKSTN-FIN-089"
                  ) do |d|
                    d.description = "vssadmin.exe delete shadows /all /quiet command executed along with hidden PowerShell C2 beaconing."
                    d.severity = "critical"
                    d.status = "new"
                    d.process_name = "vssadmin.exe"
                    d.process_id = 4920
                    d.parent_process_name = "powershell.exe"
                    d.parent_process_id = 3108
                    d.command_line = "vssadmin.exe delete shadows /all /quiet"
                    d.triggered_at = 5.minutes.ago
                  end
                end

    render json: {
      success: true,
      detection_id: detection.id,
      title: detection.title,
      severity: detection.severity,
      hostname: detection.hostname
    }
  end

  private

  def set_event_context
    if params[:ticket_id].present?
      @ticket = Ticket.find_by(id: params[:ticket_id])
      @detection = @ticket&.detection
    elsif params[:detection_id].present?
      @detection = Detection.find_by(id: params[:detection_id])
      @ticket = @detection&.tickets&.recent_first&.first
    else
      @detection = Detection.where(severity: "critical").recent_first.first || Detection.recent_first.first
      @ticket = @detection&.tickets&.recent_first&.first
    end
  end

  def serialize_ticket(t)
    {
      id: t.id,
      ticket_number: t.ticket_number,
      title: t.title,
      status: t.status,
      priority: t.priority
    }
  end
end
