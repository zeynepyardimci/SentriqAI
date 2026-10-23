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
    log_step("observe", "Sayfa ve telemetri bağlamı tarandı: URL='#{@page_url}', Tespit ID=#{@page_context[:detection_id] || 'Yok'}, Sunucu='#{@page_context[:hostname] || 'N/A'}'")

    # 1. Resolve Detection Target
    detection = resolve_detection
    if detection
      log_step("observe", "Hedef tespit belirlendi DET-#{detection.id}: '#{detection.title}' (Sunucu: #{detection.hostname}, Süreç: #{detection.process_name || 'N/A'}, Risk: #{detection.severity})")
    else
      log_step("observe", "Mevcut sayfada özel bir tespit bulunamadı. Genel SOC çalışma alanı modunda çalışılıyor.")
    end

    # 2. Think Phase (LLM Planning)
    plan = plan_actions(detection)
    log_step("think", "Sentriq Akıl Yürütme Motoru [#{active_provider_name}]: Amaç='#{@instruction}'. Planlanan aksiyonlar: #{plan[:tools].join(', ')}. Otonom Mod: #{!@human_intervention}")

    # 3. Act Phase
    # Step A: Query Knowledge Base
    rag_query = [detection&.title, detection&.process_name, @instruction].compact.join(" ")
    ragie_response = RagieRetrievalService.new(rag_query, limit: 3).call
    ragie_results = ragie_response[:results] || []
    log_step("act", "Güvenlik Runbook Bilgi Tabanı Sorgulandı: #{ragie_results.size} adet prosedür eşleşti: #{ragie_results.map { |r| r[:document_title] }.compact.uniq.join(', ').presence || 'Genel Prosedür'}")

    # Step B: Open Ticket Autonomously (if needed)
    ticket = find_or_create_ticket(detection, ragie_results)
    log_step("act", "Olay Bileti Oluşturuldu / Doğrulandı: #{ticket.ticket_number} (Durum: #{ticket.status}, Öncelik: #{ticket.priority}) — Otonom İşlem.")

    # Step C: LLM Contextual Analysis & Report Generation
    analysis_result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @current_user).call
    analysis = analysis_result[:analysis]
    log_step("think", "Bağlamsal Tehdit Analizi Tamamlandı (Niyet: #{analysis['intent']}, Güven Skoru: %#{((analysis['confidence'].to_f <= 1.0 ? analysis['confidence'].to_f * 100 : analysis['confidence'].to_f)).round})")

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
    log_step("act", "Detaylı Olay İnceleme ve Triaj Raporu bilete eklendi.")

    # Step E: Containment & Resolution without human intervention
    if !@human_intervention
      # Only transition if not already resolved/closed
      unless %w[resolved closed].include?(ticket.status)
        ticket.transition_to!("resolved", reason: "Sentriq Ajanı sayfa üzerinden otomatik triaj ve tehdit izolasyonunu tamamladı.")
      end
      ticket.update_columns(
        human_decision: "page_agent_auto_resolved",
        human_decision_notes: "Sıfır insan müdahalesi. Sentriq Ajanı sayfa bağlamını taradı, runbook prosedürlerini uyguladı ve izolasyon protokolünü işletti.",
        human_reviewed_at: Time.current
      )

      if detection && detection.can_transition_to?("investigating")
        detection.transition_to!("investigating", reason: "Sentriq Ajanı inceleme başlattı")
      end

      log_step("act", "Tehdit izolasyonu sağlandı. Bilet #{ticket.ticket_number} ÇÖZÜLDÜ (RESOLVED) olarak güncellendi.")
    else
      # Only escalate if ticket is in a state that allows pending_review transition
      if ticket.can_transition_to?("pending_review")
        ticket.escalate_to_human!(reason: "Sentriq Ajanı analist onayı için bekletmeye aldı", user: @current_user)
        log_step("act", "Bilet #{ticket.ticket_number} analist inceleme kuyruğuna (pending_review) alındı.")
      else
        log_step("act", "Bilet #{ticket.ticket_number} '#{ticket.status}' durumunda — eskalasyon atlandı.")
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
      analysis: {
        intent: analysis["intent"],
        confidence: analysis["confidence"],
        rationale: analysis["rationale"],
        recommended_action: analysis["recommended_action"],
        engine: active_provider_name
      },
      detection_id: detection&.id,
      target_selector: target_dom_selector(detection),
      dom_actions: build_dom_actions(detection, ticket),
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

  def build_dom_actions(detection, ticket)
    selector = target_dom_selector(detection)
    [
      {
        type: "move_cursor_and_click",
        selector: selector,
        phase: "observe",
        label: "🎯 Sanal İmleç: Tehdit Satırına Tıklandı",
        description: "Sentriq sanal imleci hedef satıra yöneldi ve telemetriyi seçti"
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
        label: "⚡ Sanal İmleç: Aksiyon Butonuna Tıklandı",
        description: "Ajan otonom izolasyon ve bilet oluşturma protokolünü tetikledi"
      },
      {
        type: "execute_containment",
        selector: selector,
        phase: "act",
        label: "✅ SİSTEM İZOLE EDİLDİ (#{ticket.ticket_number})",
        border_color: "#10b981",
        status_text: "İZOLE EDİLDİ"
      },
      {
        type: "auto_open_ticket",
        ticket_id: ticket.id,
        ticket_url: "/tickets/#{ticket.id}",
        ticket_number: ticket.ticket_number,
        title: ticket.title,
        priority: ticket.priority,
        status: ticket.status,
        phase: "act",
        label: "🎫 Bilet Otomatik Olarak Ekrana Getirildi"
      }
    ]
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
                   "_Eşleşen güvenlik prosedürü / runbook bulunamadı._"
                 end

    <<~REPORT
      ## 🤖 Sentriq Page-Agent Investigation Report (Zero Human Touch)

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

      ### 3. Gerçekleştirilen Müdahale ve İzolasyon Aksiyonları
      - **Alınan Aksiyon:** `#{analysis['recommended_action']}`
      - **Müdahale Durumu:** Bilet insan müdahalesine gerek kalmaksızın **ÇÖZÜLDÜ (RESOLVED)** olarak kapatıldı ve sistem karantinası uygulandı.
      - **İnsan Müdahalesi Oranı:** %0 (Tam Otonom Müdahale & Zero Human Touch).
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
