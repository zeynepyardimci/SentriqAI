# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

class AvatarConversationService
  AGENT_NAME = "Sentriq SOC Avatar Copilot"

  def initialize(query:, detection_id: nil, ticket_id: nil, current_user: nil)
    @query = query.to_s.strip
    @detection = Detection.find_by(id: detection_id) if detection_id.present?
    @ticket = Ticket.find_by(id: ticket_id) if ticket_id.present?
    @detection ||= @ticket&.detection
    @ticket ||= @detection&.tickets&.recent_first&.first
    @current_user = current_user || User.first
  end

  def call
    raise "No active security event (Detection or Ticket) selected for conversation" unless @detection || @ticket

    # Record User Message
    user_msg = CopilotMessage.create!(
      detection: @detection,
      ticket: @ticket,
      user: @current_user,
      role: "user",
      content: @query
    )

    # 1. Perform or retrieve deep investigation context
    deep_analysis = DeepInvestigationService.new(
      detection: @detection,
      ticket: @ticket,
      current_user: @current_user
    ).call

    # 2. Parse Natural Language Intent
    intent = detect_intent(@query)

    # 3. Execute Intent Action & Formulate Spoken & Written Answer
    response_payload = execute_intent_and_respond(intent, deep_analysis)

    # Record Avatar Message
    avatar_msg = CopilotMessage.create!(
      detection: @detection,
      ticket: @ticket,
      user: @current_user,
      role: "avatar",
      content: response_payload[:response],
      intent: intent.to_s,
      action_taken: response_payload[:action_taken],
      metadata: {
        speech_text: response_payload[:speech_text],
        ticket_number: @ticket&.ticket_number,
        detection_id: @detection&.id
      }
    )

    # Audit Trail
    AuditEvent.create!(
      trackable: @ticket || @detection,
      user: @current_user,
      action: "copilot_avatar_interaction",
      details: {
        query: @query,
        intent: intent,
        action_taken: response_payload[:action_taken],
        ticket_number: @ticket&.ticket_number
      }
    )

    {
      success: true,
      query: @query,
      intent: intent,
      response: response_payload[:response],
      speech_text: response_payload[:speech_text],
      action_taken: response_payload[:action_taken],
      ticket: @ticket ? serialize_ticket(@ticket) : nil,
      detection_id: @detection&.id
    }
  end

  private

  def detect_intent(text)
    t = text.downcase

    if t.include?("ticket oluştur") || t.include?("bilet oluştur") || t.include?("bilet aç") || t.include?("create ticket")
      :create_ticket
    elsif t.include?("insan incelemesi") || t.include?("eskalasyon") || t.include?("insana devret") || t.include?("escalate")
      :escalate_to_human
    elsif t.include?("kök neden") || t.include?("root cause") || t.include?("neden oldu") || t.include?("hipotez")
      :root_cause
    elsif t.include?("yönetici") || t.include?("executive") || t.include?("yöneticiye sunulacak")
      :executive_report
    elsif t.include?("önleyici") || t.include?("tedbir") || t.include?("nasıl önlenir") || t.include?("prevention") || t.include?("hardening")
      :prevention
    elsif t.include?("özet") || t.include?("ne oldu") || t.include?("olay nedir") || t.include?("summarize")
      :summarize
    elsif t.include?("bulgu") || t.include?("kanıt") || t.include?("evidence") || t.include?("hangi bulgular")
      :evidence
    elsif t.include?("neden kritik") || t.include?("önem derecesi") || t.include?("severity") || t.include?("risk nedir")
      :criticality_reason
    elsif t.include?("runbook") || t.include?("prosedür") || t.include?("playbook")
      :runbook
    elsif t.include?("durumu") || t.include?("status") || t.include?("bilet ne durumda")
      :ticket_status
    else
      :general_qa
    end
  end

  def execute_intent_and_respond(intent, deep_analysis)
    steps = deep_analysis[:steps]
    root_cause = steps[:step_5_root_cause]
    prevention = steps[:step_8_prevention]
    evidence_gaps = steps[:step_6_evidence_and_gaps]
    runbooks = steps[:step_7_runbooks]
    risk_hitl = steps[:step_9_risk_and_hitl]
    host = @detection&.hostname || "WKSTN-SEC-01"
    title = @detection&.title || @ticket&.title || "Güvenlik Alarmı"

    case intent
    when :create_ticket
      handle_create_ticket_intent(host, title)
    when :escalate_to_human
      handle_escalate_intent
    when :root_cause
      handle_root_cause_intent(root_cause)
    when :evidence
      handle_evidence_intent(evidence_gaps)
    when :prevention
      handle_prevention_intent(prevention)
    when :criticality_reason
      handle_criticality_intent(risk_hitl, host)
    when :runbook
      handle_runbook_intent(runbooks)
    when :ticket_status
      handle_ticket_status_intent
    when :executive_report
      handle_executive_report_intent(deep_analysis[:executive_summary])
    when :summarize
      handle_summarize_intent(host, title, root_cause, risk_hitl)
    else
      handle_general_qa_intent(deep_analysis)
    end
  end

  def handle_create_ticket_intent(host, title)
    action_taken = nil

    if @ticket.present?
      speech = "Bu olay için zaten kayıtlı bir bilet mevcut. Bilet numarası #{@ticket.ticket_number}, durumu #{@ticket.status}."
      body = "### 📋 Mevcut Bilet Bilgisi\nBu tespit için sistemde açık bir bilet zaten bulunmaktadır:\n- **Bilet Numarası:** `#{@ticket.ticket_number}`\n- **Öncelik:** `#{@ticket.priority.upcase}`\n- **Durum:** `#{@ticket.status}`"
      action_taken = "ticket_already_exists"
    else
      idempotency = "avatar-auto-ticket-#{@detection.id}-#{Time.current.to_i}"
      @ticket = Ticket.create!(
        title: "🛡️ [Avatar Ticket] #{title} (#{host})",
        description: "AI Avatar sesli komutu ile açılan güvenlik bileti. Hedef host: #{host}. Telemetri: #{@detection&.command_line || 'EDR alert'}.",
        priority: @detection&.severity || "high",
        status: "open",
        assigned_agent: AGENT_NAME,
        idempotency_key: idempotency,
        detection: @detection,
        user: @current_user
      )

      # Trigger contextual analysis
      TicketContextualAnalyzerService.new(ticket: @ticket, current_user: @current_user).call

      speech = "Ticket oluşturuldu. Bilet numarası #{@ticket.ticket_number}. Öncelik derecesi #{@ticket.priority.upcase} olarak kaydedildi."
      body = "### ✅ Yeni Bilet Başarıyla Oluşturuldu\n- **Bilet Numarası:** `#{@ticket.ticket_number}`\n- **Hedef:** `#{host}`\n- **Öncelik:** `#{@ticket.priority.upcase}`\n- **Durum:** `#{@ticket.status}`\n- **Atanan Ajan:** `#{AGENT_NAME}`\n\nBilet veritabanına kalıcı olarak işlendi ve triyaj motoru çalıştırıldı."
      action_taken = "ticket_created"
    end

    { response: body, speech_text: speech, action_taken: action_taken }
  end

  def handle_escalate_intent
    action_taken = nil
    if @ticket
      @ticket.escalate_to_human!(reason: "AI Avatar analist sesli/yazılı komutu ile insan incelemesine devredildi.", user: @current_user)
      speech = "Olay Seviye 2 analist incelemesi için pending review durumuna aktarıldı. Güvenlik kilidi devrede."
      body = "### ⚠️ İnsan İncelemesine Eskalasyon Yapıldı\n- **Bilet:** `#{@ticket.ticket_number}`\n- **Yeni Durum:** `pending_review`\n- **Açıklama:** Yüksek riskli müdahaleler insan onayı beklemektedir."
      action_taken = "ticket_escalated"
    else
      speech = "Henüz bilet açılmamış. Eskalasyon için önce bilet oluşturulmalıdır."
      body = "⚠️ Bu olay için henüz bir bilet açılmamış. Lütfen 'Bu olay için ticket oluştur' komutunu verin."
      action_taken = "ticket_missing"
    end
    { response: body, speech_text: speech, action_taken: action_taken }
  end

  def handle_root_cause_intent(root_cause)
    primary = root_cause[:primary]
    alternatives = root_cause[:alternatives]

    speech = "Olayın en güçlü kök neden hipotezi, yüzde #{primary[:confidence]} güvenle #{primary[:hypothesis]} olarak belirlendi."
    body = <<~MD
      ### 🎯 Olası Kök Neden Analizi
      
      **1. Birincil Kök Neden Hipotezi:**
      - **Hipotez:** `#{primary[:hypothesis]}`
      - **Güven Skoru:** %#{primary[:confidence]} (Model Sezgisel Puanı)
      - **Gerekçe:** #{primary[:rationale]}

      **2. Alternatif Senaryolar & Yanlış Pozitif Değerlendirmesi:**
      #{alternatives.map { |a| "- **#{a[:hypothesis]}** (Olasılık: #{a[:likelihood]}): #{a[:rationale]}" }.join("\n")}

      > **Önemli Not:** Kanıtlar kesinleşene kadar alternatif ihtimaller göz ardı edilmemeli; Seviye 1 triyajında kök neden tek bir mutlak gerçeklik gibi sunulmamalıdır.
    MD

    { response: body, speech_text: speech, action_taken: "root_cause_explained" }
  end

  def handle_evidence_intent(evidence_gaps)
    speech = "Olayda #{evidence_gaps[:proven_findings].size} adet kanıtlanmış bulgu ve #{evidence_gaps[:unknown_gaps].size} adet eksik bilgi tespit edildi."
    body = <<~MD
      ### 🔍 Kanıtlar, Çıkarımlar ve Bilgi Boşlukları

      **1. Kanıtlanmış Somut Bulgular (Verified Facts):**
      #{evidence_gaps[:proven_findings].map { |f| "- ✅ #{f}" }.join("\n")}

      **2. Analitik Çıkarımlar (Deductions):**
      #{evidence_gaps[:deductions].map { |d| "- 💡 #{d}" }.join("\n")}

      **3. Henüz Eksik Olan Bilgiler (Evidence Gaps):**
      #{evidence_gaps[:unknown_gaps].map { |g| "- ❓ #{g}" }.join("\n")}
    MD

    { response: body, speech_text: speech, action_taken: "evidence_detailed" }
  end

  def handle_prevention_intent(prevention)
    speech = "Acil önlem olarak ana makinenin ağ izolasyonu öneriliyor. Kalıcı önlem için PowerShell Constrained Language Mode ve ASR kuralları uygulanmalıdır."
    body = <<~MD
      ### 🛡️ Müdahale ve Önleyici Tedbirler

      **1. Acil Müdahale Adımları (Immediate Containment):**
      #{prevention[:immediate_containment].map { |c| "- 🚨 #{c}" }.join("\n")}

      **2. Kalıcı Önleme ve Güçlendirme (Hardening):**
      #{prevention[:preventive_hardening].map { |h| "- 🔒 #{h}" }.join("\n")}
    MD

    { response: body, speech_text: speech, action_taken: "prevention_explained" }
  end

  def handle_criticality_intent(risk_hitl, host)
    speech = "Olay kritik seviyede değerlendirildi. Çünkü şüpheli süreç yetkisiz kod yürütme ve sistem bütünlüğünü tahrip etme potansiyeline sahiptir."
    body = <<~MD
      ### ⚠️ Olayın Önem ve Risk Derecesi
      - **Değerlendirilen Risk:** `#{risk_hitl[:overall_risk]}`
      - **Etkilenen Ana Makine:** `#{host}`
      - **Neden Kritik?:** Tespit edilen süreç ve argümanlar doğrudan sistem kurtarmayı engelleme veya uzaktan komut yürütme yeteneğine sahiptir.
      - **İnsan Onayı Zorunluluğu:** `#{risk_hitl[:requires_human_approval] ? 'EVET (Kritik aksiyonlar insan onayı bekler)' : 'HAYIR'}`
    MD

    { response: body, speech_text: speech, action_taken: "criticality_explained" }
  end

  def handle_runbook_intent(runbooks)
    first_rb = runbooks.first
    speech = "İlgili kurumsal runbook: #{first_rb[:title]}. Prosedüre göre izolasyon ve süreç sonlandırma önerilmektedir."
    body = <<~MD
      ### 📖 Eşleşen Kurumsal Runbook Dokümanı
      #{runbooks.map { |r| "- **#{r[:title]}** (#{r[:category]}):\n  > \"#{r[:quote]}\"\n  _#{r[:relevance]}_" }.join("\n\n")}
    MD

    { response: body, speech_text: speech, action_taken: "runbook_cited" }
  end

  def handle_ticket_status_intent
    if @ticket
      speech = "Bilet numarası #{@ticket.ticket_number}. Öncelik #{@ticket.priority.upcase}, mevcut durum #{@ticket.status}."
      body = "### 📌 Bilet Durumu\n- **Numara:** `#{@ticket.ticket_number}`\n- **Durum:** `#{@ticket.status}`\n- **Öncelik:** `#{@ticket.priority.upcase}`\n- **Oluşturulma:** `#{@ticket.created_at.strftime('%Y-%m-%d %H:%M:%S')}`\n- **SLA:** 15 dakikalık yanıt eşiği devrede."
    else
      speech = "Bu olay için henüz bilet açılmamış."
      body = "Bu olay için henüz bir bilet bulunmamaktadır."
    end
    { response: body, speech_text: speech, action_taken: "status_provided" }
  end

  def handle_executive_report_intent(exec_summary)
    speech = "Yönetici özeti hazırlandı: Olay incelendi, olası kök neden belirlendi, bilet açıldı ve insan onayı aşamasına getirildi."
    { response: "```text\n#{exec_summary}\n```", speech_text: speech, action_taken: "executive_report_provided" }
  end

  def handle_summarize_intent(host, title, root_cause, risk_hitl)
    hyp = root_cause[:primary][:hypothesis]
    speech = "#{host} üzerindeki #{title} olayı incelendi. Olası kök neden #{hyp} olarak değerlendirildi."
    body = <<~MD
      ### 📝 Olay Özeti
      - **Olay:** `#{title}`
      - **Hedef:** `#{host}`
      - **Olası Kök Neden:** `#{hyp}`
      - **Risk Seviyesi:** `#{risk_hitl[:overall_risk]}`
      - **Önerilen Müdahale:** İlgili süreçlerin sonlandırılması ve Seviye 2 analist doğrulaması.
    MD
    { response: body, speech_text: speech, action_taken: "summarized" }
  end

  def handle_general_qa_intent(deep_analysis)
    live_response = request_live_llm_if_available(deep_analysis)
    if live_response
      speech = live_response.truncate(180).gsub(/[*#`_]/, "")
      { response: live_response, speech_text: speech, action_taken: "live_llm_qa" }
    else
      host = @detection&.hostname || "WKSTN"
      title = @detection&.title || @ticket&.title || "Olay"
      speech = "Sentriq AI bağlamı inceledi. Bu olay #{host} üzerindeki #{title} tespitine aittir."
      body = <<~MD
        ### 🤖 Sentriq AI Yanıtı
        Sorduğunuz soru: *"#{@query}"*

        Bu olay (**#{title}**) için telemetri ve runbook kayıtları incelenmiştir:
        - **Hedef Makine:** `#{host}`
        - **Süreç:** `#{@detection&.process_name || 'N/A'}` (PID: #{@detection&.process_id || 'N/A'})
        - **Kök Neden İpuçları:** #{deep_analysis[:steps][:step_5_root_cause][:primary][:hypothesis]}
        - **Tavsiye:** Daha fazla detay için "Bulguları özetle", "Kök neden analizini göster" veya "Bu olay için ticket oluştur" diyebilirsiniz.
      MD
      { response: body, speech_text: speech, action_taken: "local_context_qa" }
    end
  end

  def request_live_llm_if_available(deep_analysis)
    return nil unless live_api_configured?

    prompt = <<~PROMPT
      Kullanıcı sorusu: "#{@query}"
      
      === İNCELENEN GÜVENLİK OLAYI BAĞLAMI ===
      Başlık: #{@detection&.title || @ticket&.title}
      Önem: #{@detection&.severity || @ticket&.priority}
      Host: #{@detection&.hostname}
      Süreç: #{@detection&.process_name} (Komut: #{@detection&.command_line})
      Kök Neden: #{deep_analysis[:steps][:step_5_root_cause][:primary][:hypothesis]}
      Runbook: #{deep_analysis[:steps][:step_7_runbooks].first[:title]}

      Kurallar:
      1. Yalnızca bu telemetriye ve runbook'a dayalı gerçekçi yanıt ver.
      2. Kanıtlanmış bulguları çıkarımlardan ayır. Uydurma bilgi ekleme.
      3. Kısa bir özetle başla, ardından teknik gerekçeye değin. Türkçe yanıt ver.
    PROMPT

    if ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
      call_grok_chat(prompt)
    elsif ENV["OPENAI_API_KEY"].present?
      call_openai_chat(prompt)
    elsif ENV["GEMINI_API_KEY"].present?
      call_gemini_chat(prompt)
    else
      nil
    end
  rescue StandardError => e
    Rails.logger.warn("[AvatarConversationService] Live LLM call failed: #{e.message}")
    nil
  end

  def live_api_configured?
    ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present? || ENV["OPENAI_API_KEY"].present? || ENV["GEMINI_API_KEY"].present?
  end

  def call_grok_chat(prompt)
    api_key = ENV["GROK_API_KEY"].presence || ENV["XAI_API_KEY"]
    uri = URI.parse("https://api.x.ai/v1/chat/completions")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 20

    req = Net::HTTP::Post.new(uri.request_uri)
    req["Authorization"] = "Bearer #{api_key}"
    req["Content-Type"] = "application/json"
    req.body = {
      model: ENV.fetch("GROK_MODEL", "grok-2-latest"),
      messages: [
        { role: "system", content: "Sen Sentriq AI SOC Copilot Avatarısın. Kısa, teknik ve güvenilir yanıtlar ver." },
        { role: "user", content: prompt }
      ],
      temperature: 0.2
    }.to_json

    res = http.request(req)
    return nil unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body).dig("choices", 0, "message", "content")
  end

  def call_openai_chat(prompt)
    uri = URI.parse("https://api.openai.com/v1/chat/completions")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 20

    req = Net::HTTP::Post.new(uri.request_uri)
    req["Authorization"] = "Bearer #{ENV['OPENAI_API_KEY']}"
    req["Content-Type"] = "application/json"
    req.body = {
      model: ENV.fetch("OPENAI_MODEL", "gpt-4o-mini"),
      messages: [
        { role: "system", content: "Sen Sentriq AI SOC Copilot Avatarısın. Kısa, teknik ve güvenilir yanıtlar ver." },
        { role: "user", content: prompt }
      ],
      temperature: 0.2
    }.to_json

    res = http.request(req)
    return nil unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body).dig("choices", 0, "message", "content")
  end

  def call_gemini_chat(prompt)
    api_key = ENV["GEMINI_API_KEY"]
    model = ENV.fetch("GEMINI_MODEL", "gemini-1.5-flash")
    url = "https://generativelanguage.googleapis.com/v1beta/models/#{model}:generateContent?key=#{api_key}"
    uri = URI.parse(url)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 20

    req = Net::HTTP::Post.new(uri.request_uri)
    req["Content-Type"] = "application/json"
    req.body = {
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2 }
    }.to_json

    res = http.request(req)
    return nil unless res.is_a?(Net::HTTPSuccess)
    JSON.parse(res.body).dig("candidates", 0, "content", "parts", 0, "text")
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
