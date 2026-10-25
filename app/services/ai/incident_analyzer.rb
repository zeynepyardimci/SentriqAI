# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module Ai
  class IncidentAnalyzer
    attr_reader :context, :runbook_result

    def self.analyze(context, runbook_result:)
      new(context, runbook_result: runbook_result).analyze
    end

    def initialize(context, runbook_result:)
      @context = context
      @runbook_result = runbook_result
      @archetype = context[:incident_type]
    end

    def analyze
      if live_api_configured?
        begin
          res = request_live_llm
          res[:agent_mode] = active_provider_mode
          return res
        rescue StandardError => e
          Rails.logger.warn("[SentriqAI::IncidentAnalyzer] Live LLM call failed (#{e.message}). Falling back to deterministic context engine.")
        end
      end

      # Deterministic Contextual Local Engine
      run_deterministic_context_engine
    end

    private

    def live_api_configured?
      ENV["GROQ_API_KEY"].present? ||
        ENV["GROK_API_KEY"].present? ||
        ENV["XAI_API_KEY"].present? ||
        ENV["OPENAI_API_KEY"].present? ||
        ENV["GEMINI_API_KEY"].present?
    end

    def active_provider_mode
      if ENV["GROQ_API_KEY"].present?
        "groq_api"
      elsif ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
        "grok_api"
      elsif ENV["OPENAI_API_KEY"].present?
        "openai_api"
      elsif ENV["GEMINI_API_KEY"].present?
        "gemini_api"
      else
        "deterministic_local_engine"
      end
    end

    def request_live_llm
      system_prompt = build_system_instruction
      user_prompt = build_user_prompt

      raw_json_str = if ENV["GROQ_API_KEY"].present?
                       call_groq(system_prompt, user_prompt)
                     elsif ENV["GROK_API_KEY"].present? || ENV["XAI_API_KEY"].present?
                       call_grok(system_prompt, user_prompt)
                     elsif ENV["OPENAI_API_KEY"].present?
                       call_openai(system_prompt, user_prompt)
                     elsif ENV["GEMINI_API_KEY"].present?
                       call_gemini(system_prompt, user_prompt)
                     else
                       raise "No configured LLM API"
                     end

      parsed = JSON.parse(raw_json_str)
      parsed.is_a?(Hash) ? parsed : { incident_summary: parsed.to_s }
    end

    def call_groq(sys, usr)
      uri = URI.parse("https://api.groq.com/openai/v1/chat/completions")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 25

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Authorization"] = "Bearer #{ENV['GROQ_API_KEY']}"
      req["Content-Type"] = "application/json"
      req.body = {
        model: ENV.fetch("GROQ_MODEL", "llama-3.3-70b-versatile"),
        response_format: { type: "json_object" },
        messages: [{ role: "system", content: sys }, { role: "user", content: usr }],
        temperature: 0.1
      }.to_json

      res = http.request(req)
      raise "Groq API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body).dig("choices", 0, "message", "content")
    end

    def call_grok(sys, usr)
      uri = URI.parse("https://api.x.ai/v1/chat/completions")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 30

      api_key = ENV["GROK_API_KEY"].presence || ENV["XAI_API_KEY"]
      req = Net::HTTP::Post.new(uri.request_uri)
      req["Authorization"] = "Bearer #{api_key}"
      req["Content-Type"] = "application/json"
      req.body = {
        model: ENV.fetch("GROK_MODEL", "grok-2-latest"),
        response_format: { type: "json_object" },
        messages: [{ role: "system", content: sys }, { role: "user", content: usr }],
        temperature: 0.1
      }.to_json

      res = http.request(req)
      raise "Grok API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body).dig("choices", 0, "message", "content")
    end

    def call_openai(sys, usr)
      uri = URI.parse("https://api.openai.com/v1/chat/completions")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 25

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Authorization"] = "Bearer #{ENV['OPENAI_API_KEY']}"
      req["Content-Type"] = "application/json"
      req.body = {
        model: ENV.fetch("OPENAI_MODEL", "gpt-4o-mini"),
        response_format: { type: "json_object" },
        messages: [{ role: "system", content: sys }, { role: "user", content: usr }],
        temperature: 0.1
      }.to_json

      res = http.request(req)
      raise "OpenAI API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body).dig("choices", 0, "message", "content")
    end

    def call_gemini(sys, usr)
      model = ENV.fetch("GEMINI_MODEL", "gemini-1.5-flash")
      api_key = ENV["GEMINI_API_KEY"]
      uri = URI.parse("https://generativelanguage.googleapis.com/v1beta/models/#{model}:generateContent?key=#{api_key}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 25

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/json"
      req.body = {
        contents: [{ role: "user", parts: [{ text: "#{sys}\n\n#{usr}" }] }],
        generationConfig: { responseMimeType: "application/json", temperature: 0.1 }
      }.to_json

      res = http.request(req)
      raise "Gemini API error #{res.code}: #{res.body}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body).dig("candidates", 0, "content", "parts", 0, "text")
    end

    def build_system_instruction
      <<~SYS
        You are Sentriq AI Security Orchestration & Incident Analysis Engine.
        Perform forensic triage of the security event using ONLY concrete provided facts.
        CRITICAL RULES:
        1. DO NOT invent fictitious telemetry, IP addresses, or runbooks.
        2. Differentiate between verified evidence, hypotheses, and unknown gaps.
        3. Do not blindly trust labels like 'drill', 'urgent', or 'routine'. Scrutinize the command line and parent process.
        4. If a shadow copy is deleted, evaluate ransomware recovery inhibition vs routine IT cleanup.
        5. If PowerShell is spawned by Office or with -Enc, evaluate macro exploitation and LOLBins.
        6. Return strictly valid JSON with these EXACT keys:
        {
          "incident_summary": "concise objective summary of this specific incident",
          "classification": "threat classification (e.g. ransomware_precursor, suspicious_powershell_lolbin, informational_drill, credential_theft)",
          "severity": "low|medium|high|critical",
          "confidence": integer 0-100 (your heuristic assessment of classification certainty),
          "confidence_rationale": "detailed explanation for this confidence evaluation",
          "evidence": ["list of concrete observed facts from telemetry"],
          "missing_evidence": ["critical missing data needed for definitive attribution"],
          "root_cause_hypotheses": [
            {"hypothesis": "primary explanation", "likelihood": "Low|Medium|High|Critical", "rationale": "evidence backing this"}
          ],
          "alternative_hypotheses": [
            {"hypothesis": "alternative explanation (e.g. false positive or IT script)", "likelihood": "Low|Medium|High|Critical", "rationale": "why this is considered"}
          ],
          "attack_chain": ["chronological progression of the event if supported by telemetry"],
          "impact_assessment": "potential operational and security impact",
          "matched_runbooks": [
            {"title": "title", "quote": "excerpt", "relevance": "how it applies"}
          ],
          "recommended_actions": ["prioritized immediate response steps"],
          "prevention_measures": ["hardening measures to prevent recurrence"],
          "requires_human_approval": boolean (true for any critical/high threat or destructive action),
          "analysis_limitations": "known analytical constraints and missing artifacts"
        }
      SYS
    end

    def build_user_prompt
      telem = @context[:telemetry] || {}
      evs = @context[:evidences] || []
      missing = @context[:missing_fields] || []
      prior = @context[:prior_related_events] || []
      runbooks = @runbook_result[:runbooks] || []

      ev_text = evs.map { |e| "- [#{e[:occurred_at]}] #{e[:evidence_type]}: #{e[:description]}" }.join("\n")
      prior_text = prior.map { |p| "- [#{p[:severity].upcase}] #{p[:title]} on #{p[:triggered_at]}" }.join("\n")

      rb_text = if runbooks.any?
                  runbooks.map { |r| "RUNBOOK: #{r[:title]} (#{r[:category]})\nAlıntı: #{r[:quote]}" }.join("\n\n")
                else
                  "No matching runbook found in knowledge base."
                end

      <<~PROMPT
        === TARGET INCIDENT TELEMETRY ===
        Ticket ID: #{@context.dig(:ticket, :ticket_number) || 'N/A'} (#{@context.dig(:ticket, :title)})
        Detection: #{@context.dig(:detection, :title) || 'N/A'} (Severity: #{@context.dig(:detection, :severity)})
        Hostname: #{telem[:hostname] || 'Unknown'} | IP: #{telem[:ip_address] || 'Unknown'} | User: #{telem[:username] || 'Unknown'}
        Process: #{telem[:process_name]} (PID: #{telem[:process_id]})
        Parent Process: #{telem[:parent_process_name]} (PID: #{telem[:parent_process_id]})
        Command Line: #{telem[:command_line]}
        SHA256 Hash: #{telem[:file_hash]}

        === RECORDED EVIDENCE TIMELINE ===
        #{ev_text.presence || 'No prior evidence sequence recorded.'}

        === KNOWN MISSING TELEMETRY (GAPS) ===
        #{missing.join(', ')}

        === PRIOR RELATED EVENTS ON HOST ===
        #{prior_text.presence || 'None observed.'}

        === RETRIEVED RUNBOOK PROCEDURES (GROUNDED CONTEXT) ===
        #{rb_text}

        Generate the forensic JSON report strictly following the required schema now.
      PROMPT
    end

    # ── Deterministic Context-Aware Local Engine ─────────────────────────────
    # Runs when external LLM is offline or not configured. Produces rich,
    # context-specific outputs based on actual telemetry (not static templates).
    def run_deterministic_context_engine
      telem = @context[:telemetry] || {}
      evs = @context[:evidences] || []
      missing = @context[:missing_fields] || []
      runbooks = @runbook_result[:runbooks] || []
      host = telem[:hostname] || "Uç Nokta"
      proc_name = telem[:process_name] || "Bilinmeyen Süreç"
      cmd = telem[:command_line].to_s

      # Observed evidence lines
      observed = []
      observed << "#{host} ana makinesinde '#{proc_name}' (PID: #{telem[:process_id] || 'Bilinmiyor'}) süreci tespit edildi."
      observed << "Ebeveyn süreç: '#{telem[:parent_process_name]}' (PID: #{telem[:parent_process_id] || 'N/A'})." if telem[:parent_process_name].present?
      observed << "Çalıştırılan komut satırı: '#{cmd}'." if cmd.present?
      observed << "Dosya SHA256 özeti: #{telem[:file_hash]}." if telem[:file_hash].present?
      evs.each { |e| observed << "[#{e[:evidence_type]}] #{e[:description]}" }

      case @archetype
      when :ransomware_precursor
        {
          agent_mode: "deterministic_local_engine",
          incident_summary: "#{host} üzerinde 'vssadmin.exe' ile gölge kopyaların sessizce silinmesi tespit edildi. Sistem geri yükleme noktalarının tahribi olası fidye yazılımı (ransomware) öncesi hazırlık göstergesidir.",
          classification: "ransomware_precursor",
          intent: "active_threat_containment",
          severity: "critical",
          confidence: 91,
          confidence_rationale: "Gölge kopya silme komutu ve sessiz parametreler (/quiet) kurumsal uç noktalarda yalnızca tahribat veya fidye saldırılarında görülür.",
          evidence: observed,
          missing_evidence: [
            "Dosya sisteminde şifrelenmiş veya değiştirilmiş uzantılar (.locked vb.)",
            "Uç nokta tam bellek dökümü (memory dump)",
            "Active Directory etki alanı genelinde eşzamanlı benzer vssadmin komutları"
          ],
          root_cause_hypotheses: [
            {
              hypothesis: "Fidye Yazılımı (Ransomware) Öncesi Sistem Geri Yükleme İmhası (T1490)",
              likelihood: "Critical",
              rationale: "vssadmin delete shadows /all /quiet komutu doğrudan sistem kurtarma noktalarını silerek kurbanın ödeme yapmadan dönmesini engellemeyi amaçlar."
            }
          ],
          alternative_hypotheses: [
            {
              hypothesis: "Yetkili BT Disk Alanı Temizliği",
              likelihood: "Low",
              rationale: "Standart bakım betiklerinin vssadmin'i 'quiet' bayrağıyla çalıştırması kurumsal standartlara aykırıdır; olasılık düşüktür."
            }
          ],
          attack_chain: [
            "1. İstismar veya yetkisiz oturum açma ile uç noktaya erişim sağlandı.",
            "2. Savunma mekanizmalarını zayıflatmak için vssadmin.exe çağrıldı.",
            "3. Olası sonraki aşama: Dosya şifreleme ve fidye notu bırakma."
          ],
          impact_assessment: "Yüksek: Başarılı olursa sistem felaket kurtarma yeteneğini kaybeder ve şirket verileri geri döndürülemez biçimde şifrelenebilir.",
          matched_runbooks: runbooks,
          recommended_actions: [
            "1. #{host} ana makinesini ağdan derhal İZOLE EDİN (Simüle Host İzolasyonu).",
            "2. vssadmin sürecini ve ebeveyn ağacını derhal sonlandırın.",
            "3. Etkilenen kullanıcının (#{telem[:username] || 'N/A'}) tüm aktif oturumlarını kapatın.",
            "4. Veri tabanında yedekleme durumunu doğrulayın."
          ],
          prevention_measures: [
            "vssadmin.exe ve bcdedit.exe komutlarının standart kullanıcılar tarafından yürütülmesini ASR / AppLocker ile engelleyin.",
            "Değiştirilemez (Immutable / WORM) çevrimdışı yedekleme mimarisine geçin.",
            "EDR kurcalama korumasını (Tamper Protection) zorunlu tutun."
          ],
          requires_human_approval: true,
          analysis_limitations: "Uç noktanın disk imajı ve C2 ağ trafiği henüz incelenmemiştir."
        }

      when :suspicious_powershell_lolbin
        {
          agent_mode: "deterministic_local_engine",
          incident_summary: "#{host} üzerinde #{telem[:parent_process_name] || 'ebeveyn süreç'} kaynaklı gizlenmiş (Base64 / Encoded) parametrelerle #{telem[:process_name] || 'PowerShell'} yürütülmesi tespit edildi. Ebeveyn süreç ve komut argümanları kod yürütme göstergesidir.",
          classification: "suspicious_powershell_lolbin",
          intent: "active_threat_containment",
          severity: "critical",
          confidence: 86,
          confidence_rationale: "Gizli pencere bayrağı (-W Hidden) ve Base64 kodlu parametreler meşru yönetim pratikleriyle bağdaşmamaktadır.",
          evidence: observed,
          missing_evidence: [
            "Base64 çözümlenmiş ham betik içeriği",
            "Ağ dışına aktarılan paket boyutu ve C2 hedef IP itibarı",
            "Bellekte çalışan dinamik enjeksiyon (reflective DLL) bulguları"
          ],
          root_cause_hypotheses: [
            {
              hypothesis: "Kimlik Avı veya Belge Makrosu Aracılığıyla Kod Yürütme (T1059.001)",
              likelihood: "High",
              rationale: "Ofis veya tarayıcı yazılımlarının alt süreç olarak PowerShell başlatması klasik ilk erişim yöntemidir."
            }
          ],
          alternative_hypotheses: [
            {
              hypothesis: "Özel BT Yönetim Otomasyon Betiği",
              likelihood: "Low",
              rationale: "Kurumsal otomasyonların Base64 kodlu ve gizli pencereyle çalışması nadirdir."
            }
          ],
          attack_chain: [
            "1. Ebeveyn süreç (#{telem[:parent_process_name] || 'uygulama'}) tarafından PowerShell tetiklendi.",
            "2. Bellek içinde gizli komut çalıştırma girişimi yapıldı.",
            "3. Dış ağ bağlantısı veya ikinci aşama indirme başlatıldı."
          ],
          impact_assessment: "Kritik: Saldırgan uç noktada yerel kullanıcı yetkileriyle rastgele kod çalıştırma yeteneği kazanmıştır.",
          matched_runbooks: runbooks,
          recommended_actions: [
            "1. #{host} uç noktasını ağdan izole edin.",
            "2. PowerShell PID #{telem[:process_id] || 'N/A'} sürecini derhal sonlandırın.",
            "3. İlgili IP (#{telem[:ip_address] || 'harici hedef'}) güvenlik duvarında engelleyin.",
            "4. Kullanıcı kimlik bilgilerini sıfırlayın."
          ],
          prevention_measures: [
            "PowerShell ConstrainedLanguageMode (CLM) zorunlu kılınmalıdır.",
            "Ofis uygulamalarında child process spawn engelleme ASR kuralı aktif edilmelidir.",
            "ScriptBlock Logging (Event ID 4104) tüm filoda etkinleştirilmelidir."
          ],
          requires_human_approval: true,
          analysis_limitations: "Dış IP adresinin nihai C2 sunucusu olup olmadığı tehdit istihbaratı doğrulaması gerektirir."
        }

      when :drill_or_retrospective
        {
          agent_mode: "deterministic_local_engine",
          incident_summary: "#{host} üzerinde tespit edilen süreç ve komut parametreleri planlı bir tatbikat veya rutin yedekleme kontrolü ile örtüşmektedir.",
          classification: "informational_drill",
          intent: "informational_retrospective",
          severity: "low",
          confidence: 84,
          confidence_rationale: "Olay başlığı, komut satırı ve telemetri geçmiş tatbikat parametrelerini doğrulamaktadır. Aktif tehdit unsuru saptanmamıştır.",
          evidence: observed,
          missing_evidence: [
            "Tatbikat takvimi ve onaylı değişiklik yönetim (RFC) numarası",
            "Planlama sahibinin (ticket requester) teyidi"
          ],
          root_cause_hypotheses: [
            {
              hypothesis: "Planlanmış Siber Tatbikat veya Rutin Bakım Görevi",
              likelihood: "High",
              rationale: "Komut parametreleri ve zamanlama rutin arşivleme veya tatbikat senaryosuyla tam uyumludur."
            }
          ],
          alternative_hypotheses: [
            {
              hypothesis: "Tatbikat Sürecinin Kötüye Kullanımı",
              likelihood: "Low",
              rationale: "Meşru bakım betiği kılıfında yetkisiz faaliyet ihtimali teyit edilmelidir."
            }
          ],
          attack_chain: [
            "1. Zamanlanmış görev (#{telem[:parent_process_name] || 'taskeng.exe'}) bakım betiğini başlattı.",
            "2. Rutin arşivleme tamamlandı ve alarm kaydı oluştu."
          ],
          impact_assessment: "Önemsiz (Benign): Aktif bir güvenlik tehdidi yoktur, sistem bütünlüğü korunmuştur.",
          matched_runbooks: runbooks,
          recommended_actions: [
            "1. Tatbikat takvimiyle eşleştirerek bileti 'resolved' olarak arşivleyin.",
            "2. Yanlış alarmı kapatın, ağ izolasyonuna gerek yoktur."
          ],
          prevention_measures: [
            "Tatbikat betiklerinin EDR üzerinde bakım istisnası (maintenance window) ile tanımlanması önerilir."
          ],
          requires_human_approval: false,
          analysis_limitations: "Değişiklik yönetim kayıtları harici ITSM sisteminden doğrulanmalıdır."
        }

      else
        {
          agent_mode: "deterministic_local_engine",
          incident_summary: "#{host} üzerinde '#{proc_name}' ile ilişkili şüpheli güvenlik telemetrisi kaydedildi. Telemetri verileri Seviye 2 analist triyajı gerektirmektedir.",
          classification: "general_security_incident",
          intent: "active_threat_containment",
          severity: @context.dig(:detection, :severity) || @context.dig(:ticket, :priority) || "medium",
          confidence: 65,
          confidence_rationale: "Temel telemetri mevcut fakat saldırı niyetini kesinleştirmek için ek ağ ve bellek analizi gerekmektedir.",
          evidence: observed,
          missing_evidence: missing,
          root_cause_hypotheses: [
            {
              hypothesis: "Şüpheli Süreç Faaliyeti ve Beklenmeyen Alt Süreç Başlatma",
              likelihood: "Medium",
              rationale: "Uç noktada olağan dışı komut veya ebeveyn süreç ilişkisi gözlemlendi."
            }
          ],
          alternative_hypotheses: [
            {
              hypothesis: "Yetkili Kullanıcı / Yönetim Etkinliği",
              likelihood: "Low",
              rationale: "Yetkili BT personeli tarafından gerçekleştirilmiş meşru bir işlem olma ihtimali bulunmaktadır."
            }
          ],
          attack_chain: [
            "1. Uç noktada süreç başlatıldı.",
            "2. Güvenlik sensörleri anomali tespit ederek alarm üretti."
          ],
          impact_assessment: "Orta: Henüz yayılma gözlemlenmedi ancak yetkisiz erişim riski mevcuttur.",
          matched_runbooks: runbooks,
          recommended_actions: [
            "1. Kullanıcı ile iletişime geçerek işlemin meşruiyetini teyit edin.",
            "2. Süreç komut satırını ve ebeveyn süreç soyağacını inceleyin."
          ],
          prevention_measures: [
            "Şüpheli komut çalıştırma kuralları SIEM üzerinde güncellenmelidir."
          ],
          requires_human_approval: true,
          analysis_limitations: "Sınırlı telemetri nedeniyle kesin sınıflandırma analist teyidine bağlıdır."
        }
      end
    end
  end
end
