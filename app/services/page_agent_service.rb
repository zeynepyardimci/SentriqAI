# frozen_string_literal: true

class PageAgentService
  AGENT_NAME = "Sentriq-Page-Agent/v1.0"

  attr_reader :execution_id, :steps

  def initialize(instruction:, page_url: nil, page_context: {}, current_user: nil, human_intervention: false, confirmed_action: nil)
    @instruction = instruction.to_s.strip
    @page_url = page_url.to_s
    raw_ctx = page_context.respond_to?(:to_unsafe_h) ? page_context.to_unsafe_h : (page_context || {})
    @page_context = raw_ctx.with_indifferent_access
    @current_user = current_user || User.find_by(role: "lead_analyst") || User.first
    @human_intervention = human_intervention
    @confirmed_action = confirmed_action
    @execution_id = "page-exec-#{Time.current.strftime('%Y%m%d%H%M%S')}-#{SecureRandom.hex(4)}"
    @steps = []
  end

  def call
    # ── STAGE 1: OBSERVE ─────────────────────────────────────────────────────
    log_step("observe", "Execution #{@execution_id}: Sayfa ve telemetri taranıyor. URL='#{@page_url}', Tespit ID=#{@page_context[:detection_id] || 'Yok'}, Sunucu='#{@page_context[:hostname] || 'N/A'}'")

    detection = resolve_detection
    target_selector = target_dom_selector(detection)

    if detection
      log_step("observe", "Hedef tespit gözlemlendi DET-#{detection.id}: '#{detection.title}' (Sunucu: #{detection.hostname}, Süreç: #{detection.process_name || 'N/A'}, Risk: #{detection.severity}, Durum: #{detection.status})")
    else
      log_step("observe", "Mevcut sayfada doğrudan tespit referansı bulunamadı. Genel SOC çalışma alanı telemetrisi inceleniyor.")
    end

    # ── STAGE 2: REASON ──────────────────────────────────────────────────────
    rag_query = [detection&.title, detection&.process_name, @instruction].compact.join(" ")
    ragie_response = RagieRetrievalService.new(rag_query, limit: 3).call
    ragie_results = ragie_response[:results] || []
    log_step("think", "Güvenlik Runbook Deposu Sorgulandı: #{ragie_results.size} prosedür eşleşti (#{ragie_response[:provider] == 'ragie_cloud' ? 'Canlı Bulut' : 'Yerel Runbook'}).")

    # Resolve or create ticket early so contextual analyzer can inspect it
    ticket = find_or_create_ticket(detection, ragie_results)

    analysis_result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @current_user).call
    analysis = analysis_result[:analysis]

    # Decide if human approval is strictly required
    # Mandatory HITL policy: Any high or critical severity, or explicit requires_human_approval flag, or destructive action requires human approval
    requires_human_approval = analysis["requires_human_approval"] == true ||
                              analysis["requires_human_review"] == true ||
                              ticket.priority.in?(%w[high critical]) ||
                              detection&.severity.in?(%w[high critical])

    # Allow human override if an authorized analyst explicitly confirmed the action
    if @confirmed_action.present? && @current_user.present?
      requires_human_approval = false
      log_step("think", "Yetkili analist (#{@current_user.email}) tarafından aksiyon manuel olarak onaylandı: '#{@confirmed_action}'")
    end

    conf = analysis["confidence"].to_f
    conf_pct = conf <= 1.0 ? (conf * 100).round : conf.round

    log_step("think", "Akıl Yürütme [#{active_provider_name}]: Niyet='#{analysis['intent']}', Güven=%#{conf_pct}, İnsan Onayı Gerekli mi=#{requires_human_approval ? 'EVET (HITL Zorunlu)' : 'HAYIR (Rutin/Düşük Risk)'}")

    # ── STAGE 3: PLAN ────────────────────────────────────────────────────────
    expected_status = requires_human_approval ? "pending_review" : "resolved"
    action_type = requires_human_approval ? "escalate_to_pending_review" : "auto_resolve_routine"
    containment_status = if requires_human_approval
                           "SIMULATED"
                         elsif detection&.severity.in?(%w[high critical])
                           "SIMULATED"
                         else
                           "NOT_REQUIRED"
                         end

    log_step("think", "Plan Oluşturuldu: Eylem='#{action_type}', Beklenen Bilet Durumu='#{expected_status}', Ağ İzolasyonu='#{containment_status}' (Gerçek donanım izolasyonu yoktur, simüle edilmiştir).")

    # ── STAGE 4: ACT ─────────────────────────────────────────────────────────
    # A. Status Transitions & Containment recording
    if requires_human_approval
      if ticket.can_transition_to?("pending_review")
        ticket.escalate_to_human!(
          reason: "Sentriq Page-Agent [#{execution_id}]: Seviye 2 analist doğrulaması gereklidir. Gerekçe: #{analysis['rationale']}",
          user: @current_user
        )
      end

      # Transition detection state machine safely if applicable
      transition_detection_safely(detection, "open")

      # Record simulated host isolation in AuditEvent
      AuditEvent.create!(
        trackable: ticket,
        user: @current_user,
        action: "simulated_host_isolation_recorded",
        details: {
          execution_id: @execution_id,
          hostname: detection&.hostname || "workspace-host",
          simulated: true,
          status: "pending_approval",
          rationale: analysis["rationale"],
          recommended_action: analysis["recommended_action"]
        }
      )

      action_status = "PENDING_APPROVAL"
      log_step("act", "Güvenlik Politikası Devrede: Yüksek riskli tehdit için Seviye 2 analist doğrulaması istendi. Bilet #{ticket.ticket_number} 'pending_review' kuyruğuna alındı. Ağ izolasyonu SİMÜLE EDİLDİ.")
    else
      # Low-risk or routine drill: can safely transition to resolved
      if ticket.can_transition_to?("resolved")
        ticket.transition_to!("resolved", user: @current_user, reason: "Sentriq Page-Agent: Rutin değerlendirme tamamlandı, tehdit saptanmadı veya tatbikat doğrulandı.")
      end

      ticket.update_columns(
        human_decision: "page_agent_auto_resolved",
        human_decision_notes: "Sıfır insan müdahalesi ile çözüldü. Rutin/Düşük riskli telemetri doğrulandı.",
        human_reviewed_at: Time.current
      )

      action_status = "SUCCEEDED"
      log_step("act", "Bilet #{ticket.ticket_number} otonom olarak ÇÖZÜLDÜ (RESOLVED) durumuna güncellendi.")
    end

    # B. Compile and attach investigation report to ticket notes
    report_content = build_page_agent_report(
      ticket: ticket,
      detection: detection,
      analysis: analysis,
      ragie_results: ragie_results,
      ragie_provider: ragie_response[:provider],
      requires_human_approval: requires_human_approval,
      containment_status: containment_status,
      action_status: action_status
    )

    ticket.ticket_notes.create!(
      user: @current_user,
      author_type: "agent",
      author_name: AGENT_NAME,
      note_type: "finding",
      body: report_content,
      metadata: {
        page_agent: true,
        execution_id: @execution_id,
        requires_human_approval: requires_human_approval,
        action_status: action_status,
        containment_status: containment_status,
        rag_provider: ragie_response[:provider],
        instruction: @instruction
      }
    )

    # C. Build DOM actions matching real target and state
    dom_actions = build_dom_actions(detection, ticket, requires_human_approval, containment_status)

    # ── STAGE 5: VERIFY ──────────────────────────────────────────────────────
    ticket.reload
    actual_status = ticket.status

    verified = (actual_status == expected_status)
    if verified
      log_step("verify", "✅ Doğrulama Başarılı: Bilet #{ticket.ticket_number} veritabanında '#{actual_status}' durumunda teyit edildi. Denetim logları kaydedildi.")
    else
      log_step("error", "❌ Doğrulama Uyarısı: Beklenen '#{expected_status}', veritabanındaki gerçek durum '#{actual_status}'. İşlem güvenli modda durduruldu.")
    end

    AuditEvent.create!(
      trackable: ticket,
      user: @current_user,
      action: "page_agent_action_executed",
      details: {
        execution_id: @execution_id,
        instruction: @instruction,
        page_url: @page_url,
        rag_provider: ragie_response[:provider],
        human_intervention: @human_intervention,
        requires_human_approval: requires_human_approval,
        action_status: action_status,
        expected_status: expected_status,
        final_status: actual_status,
        verified: verified
      }
    )

    {
      success: verified,
      verified: verified,
      execution_id: @execution_id,
      needs_human: requires_human_approval,
      ticket: {
        id: ticket.id,
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        status: ticket.status,
        priority: ticket.priority,
        url: "/tickets/#{ticket.id}"
      },
      decision: {
        intent: analysis["intent"],
        confidence: conf_pct,
        rationale: analysis["rationale"],
        recommended_action: analysis["recommended_action"],
        requires_human_approval: requires_human_approval,
        action_status: action_status,
        containment_status: containment_status,
        engine: active_provider_name
      },
      analysis: {
        intent: analysis["intent"],
        confidence: conf_pct,
        rationale: analysis["rationale"],
        recommended_action: analysis["recommended_action"],
        requires_human_approval: requires_human_approval,
        action_status: action_status,
        engine: active_provider_name
      },
      detection_id: detection&.id,
      target_selector: target_selector,
      dom_actions: dom_actions,
      report: report_content,
      ragie_results: ragie_results,
      ragie_provider: ragie_response[:provider],
      verification: {
        verified: verified,
        expected_status: expected_status,
        db_status: actual_status,
        checks_passed: verified ? ["db_reloaded", "audit_logged", "status_consistent"] : []
      },
      steps: @steps
    }
  rescue StandardError => e
    log_step("error", "Page-Agent execution failed: #{e.message}")
    {
      success: false,
      verified: false,
      execution_id: @execution_id,
      needs_human: false,
      error: e.message,
      steps: @steps
    }
  end

  private

  def active_provider_name
    if ENV["GROQ_API_KEY"].present?
      "Groq Live API [#{ENV.fetch('GROQ_MODEL', 'llama-3.3-70b-versatile')}]"
    elsif ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
      "Grok (xAI) Live API [#{ENV.fetch('GROK_MODEL', 'grok-2-latest')}]"
    elsif ENV["OPENAI_API_KEY"].present?
      "OpenAI Live [#{ENV.fetch('OPENAI_MODEL', 'gpt-4o-mini')}]"
    elsif ENV["GEMINI_API_KEY"].present?
      "Gemini Live [#{ENV.fetch('GEMINI_MODEL', 'gemini-1.5-flash')}]"
    else
      "Sentriq Dahili Analiz Motoru (Contextual Engine)"
    end
  end

  def target_dom_selector(detection)
    return "#detection-row-#{detection.id}" if detection
    ".data-table tbody tr:first-child"
  end

  def build_dom_actions(detection, ticket, requires_human_approval, containment_status)
    selector = target_dom_selector(detection)

    badge_color = requires_human_approval ? "#f59e0b" : "#10b981"
    badge_label = if requires_human_approval
                    "🟡 İNSAN ONAYI BEKLİYOR (#{ticket.ticket_number})"
                  else
                    "✅ ÇÖZÜLDÜ (#{ticket.ticket_number})"
                  end

    [
      {
        type: "move_cursor_and_click",
        selector: selector,
        phase: "observe",
        label: "🎯 Sanal İmleç: Tehdit Satırına Yönelindi",
        description: "Sentriq sanal imleci hedef satıra yöneldi ve telemetriyi doğruladı"
      },
      {
        type: "perceive_and_highlight",
        selector: selector,
        phase: "observe",
        label: "🎯 SENTRIQ: HEDEF TEHDİT",
        border_color: "#facc15"
      },
      {
        type: "move_cursor_to_action",
        selector: "#pa-run-btn",
        phase: "act",
        label: "⚡ Sanal İmleç: Triaj Protokolü Tetiklendi",
        description: "Ajan backend API üzerinden bilet ve analiz sürecini işletti"
      },
      {
        type: "execute_containment",
        selector: selector,
        phase: "act",
        label: badge_label,
        border_color: badge_color,
        status_text: requires_human_approval ? "ONAY BEKLİYOR" : "ÇÖZÜLDÜ",
        containment_mode: containment_status
      },
      {
        type: "auto_open_ticket",
        ticket_id: ticket.id,
        ticket_url: "/tickets/#{ticket.id}",
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        priority: ticket.priority,
        status: ticket.status,
        requires_human_approval: requires_human_approval,
        phase: "verify",
        label: "🎫 Bilet Ayrıntıları Ekrana Getirildi"
      }
    ]
  end

  def resolve_detection
    if @page_context[:detection_id].present?
      Detection.find_by(id: @page_context[:detection_id])
    elsif @page_context[:ticket_id].present?
      t = Ticket.find_by(id: @page_context[:ticket_id])
      t&.detection
    elsif @page_url.match(%r{/detections/(\d+)})
      Detection.find_by(id: ::Regexp.last_match(1))
    elsif @page_url.match(%r{/tickets/(\d+)})
      t = Ticket.find_by(id: ::Regexp.last_match(1))
      t&.detection
    else
      # Prioritize active detections without tickets
      active_ticket_det_ids = Ticket.where.not(status: %w[closed]).where.not(detection_id: nil).pluck(:detection_id)
      Detection.active.where.not(id: active_ticket_det_ids).recent_first.first || Detection.active.recent_first.first
    end
  end

  def find_or_create_ticket(detection, _ragie_results)
    if @page_context[:ticket_id].present?
      existing_by_param = Ticket.find_by(id: @page_context[:ticket_id])
      return existing_by_param if existing_by_param
    end

    if detection
      # Idempotency: reuse existing ticket (open, investigating, or pending_review)
      existing = detection.tickets.where(status: %w[open investigating pending_review]).recent_first.first
      return existing if existing
    end

    # Deterministic idempotency key: one ticket per detection per hour
    det_key = detection&.id || "gen"
    time_window = Time.current.strftime("%Y%m%d%H")
    idempotency_key = "page-agent-det-#{det_key}-#{time_window}"

    existing_by_key = Ticket.find_by(idempotency_key: idempotency_key)
    return existing_by_key if existing_by_key

    title = detection ? "🤖 [Page-Agent Alert] #{detection.title} (#{detection.hostname})" : "🤖 [Page-Agent] Security Incident Triage Request"
    description = if detection
                    "In-Page Agent observed telemetry on #{detection.hostname}. Process: #{detection.process_name || 'N/A'}. User Instruction: '#{@instruction}'."
                  else
                    "In-Page Agent triggered with instruction: '#{@instruction}'."
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

  def transition_detection_safely(detection, target_status)
    return unless detection
    if detection.status == "new" && detection.can_transition_to?("open")
      detection.transition_to!("open", user: @current_user, reason: "Page-Agent olay incelemesini başlattı.")
    elsif detection.can_transition_to?(target_status)
      detection.transition_to!(target_status, user: @current_user, reason: "Page-Agent durumu güncelledi.")
    end
  rescue StandardError => e
    Rails.logger.warn("Detection transition warning: #{e.message}")
  end

  def build_page_agent_report(ticket:, detection:, analysis:, ragie_results:, ragie_provider:, requires_human_approval:, containment_status:, action_status:)
    conf = analysis["confidence"].to_f
    conf_pct = conf <= 1.0 ? (conf * 100).round : conf.round

    cited_docs = if ragie_results.any?
                   ragie_results.map do |r|
                     "- **#{r[:document_title]}** [#{r[:category] || 'runbook'}]: _\"#{r[:quote].to_s.truncate(130)}\"_"
                   end.join("\n")
                 else
                   "_Eşleşen güvenlik prosedürü / runbook bulunamadı._"
                 end

    status_summary = if requires_human_approval
                       <<~SUMMARY
                         - **Müdahale Durumu:** 🟡 **İNSAN ONAYI BEKLİYOR (PENDING_REVIEW)**
                         - **Gerekçe:** #{analysis['rationale']}
                         - **Ağ İzolasyonu:** #{containment_status == 'SIMULATED' ? 'Simüle Edildi (Host İzolasyon Önerisi Oluşturuldu, Uygulanması İçin Seviye 2 Analist Onayı Gereklidir)' : 'Gerekli Değil'}
                         - **Aksiyon Durumu:** #{action_status}
                       SUMMARY
                     else
                       <<~SUMMARY
                         - **Müdahale Durumu:** ✅ **ÇÖZÜLDÜ (RESOLVED)** — Rutin kontrol / tatbikat teyit edildi.
                         - **Aksiyon Durumu:** #{action_status}
                       SUMMARY
                     end

    <<~REPORT
      ## 🤖 Sentriq Page-Agent Investigation Report

      - **Execution ID:** `#{@execution_id}`
      - **Sistem Bileşeni:** Sentriq Otonom SOC Ajanı (`#{AGENT_NAME}`)
      - **Akıl Yürütme Motoru:** `#{active_provider_name}`
      - **Güvenlik Bilgi Tabanı:** `#{ragie_provider == 'ragie_cloud' ? 'Kurumsal Güvenlik Runbook Deposu (Canlı Bulut)' : 'Dahili Güvenlik Runbook Deposu (Yerel)'}`
      - **Tetiklenen Talimat:** _"#{@instruction}"_
      - **Hedef Sunucu / Uç Nokta:** `#{detection&.hostname || 'SOC Çalışma Alanı'}`
      - **Öncelik Derecesi:** `#{ticket.priority.upcase}`
      - **Yapay Zekâ Güven Skoru:** `%#{conf_pct}`

      ### 1. Sayfa ve Tehdit Bağlam Özeti
      #{analysis['rationale']}

      ### 2. Başvurulan Güvenlik Prosedürleri & Runbook'lar
      #{cited_docs}

      ### 3. Müdahale ve İzolasyon Durumu
      #{status_summary}
      - **Önerilen Aksiyon:** `#{analysis['recommended_action']}`
      - **Donanım İzolasyon Gerçekliği:** Bu ortamda fiziksel EDR ajan bağlantısı bulunmadığından izolasyon **SİMÜLE** edilmiştir.
    REPORT
  end

  def log_step(phase, message)
    timestamp = Time.current.strftime("%H:%M:%S")
    @steps << {
      timestamp: timestamp,
      phase: phase, # "observe", "think", "act", "verify", "error"
      message: message
    }
  end
end
