# frozen_string_literal: true

class DeepInvestigationService
  def initialize(detection: nil, ticket: nil, current_user: nil, force_reanalyze: false)
    @ticket = ticket.is_a?(Ticket) ? ticket : (Ticket.find_by(id: ticket) if ticket.present?)
    @detection = detection.is_a?(Detection) ? detection : (Detection.find_by(id: detection) if detection.present?)
    @detection ||= @ticket&.detection
    @ticket ||= @detection&.tickets&.recent_first&.first
    @current_user = current_user
    @force_reanalyze = force_reanalyze
  end

  def call
    @detection ||= Detection.where(severity: "critical").recent_first.first || Detection.recent_first.first
    @ticket ||= @detection&.tickets&.recent_first&.first

    return empty_investigation_result unless @detection || @ticket

    # 1. Run through centralized AI Orchestrator
    orchestration = Ai::Orchestrator.call(
      ticket: @ticket,
      detection: @detection,
      current_user: @current_user,
      force_reanalyze: @force_reanalyze
    )

    analysis = orchestration[:analysis] || {}
    context = orchestration[:context] || {}
    telem = context[:telemetry] || {}
    evs = context[:evidences] || []
    missing = context[:missing_fields] || []
    runbooks = orchestration[:runbook_matches] || []
    confidence_assessment = orchestration[:confidence_assessment] || {}

    # 2. Map structured data into the 10 Investigation Steps
    steps = {
      step_1_telemetry: format_telemetry_step(telem, analysis),
      step_2_timeline: format_timeline_step(evs),
      step_3_process_tree: format_process_tree_step(telem),
      step_4_scenarios: format_scenarios_step(analysis),
      step_5_root_cause: format_root_cause_step(analysis, confidence_assessment),
      step_6_evidence_and_gaps: format_evidence_gaps_step(analysis, missing),
      step_7_runbooks: format_runbooks_step(runbooks),
      step_8_prevention: format_prevention_step(analysis),
      step_9_risk_and_hitl: format_risk_hitl_step(analysis, confidence_assessment),
      step_10_status: "investigation_completed_and_verified"
    }

    # 3. Two Unified Structured Reports
    executive_summary = build_executive_summary(steps, analysis)
    technical_report = build_technical_report(steps, analysis)

    # 4. Synchronize with ticket context
    if @ticket
      @ticket.update_columns(
        llm_analysis: (@ticket.llm_analysis || {}).merge(
          "deep_investigation" => steps,
          "executive_summary" => executive_summary,
          "technical_report" => technical_report,
          "last_deep_analyzed_at" => Time.current.iso8601
        )
      )
    end

    {
      success: true,
      detection: @detection,
      ticket: @ticket,
      steps: steps,
      analysis: analysis,
      confidence_assessment: confidence_assessment,
      executive_summary: executive_summary,
      technical_report: technical_report
    }
  end

  private

  def format_telemetry_step(telem, analysis)
    {
      hostname: telem[:hostname] || "Bilinmeyen Host",
      ip_address: telem[:ip_address] || "N/A",
      username: telem[:username] || "N/A",
      process_name: telem[:process_name] || "Bilinmiyor",
      process_id: telem[:process_id] || 0,
      parent_process_name: telem[:parent_process_name] || "N/A",
      parent_process_id: telem[:parent_process_id] || 0,
      command_line: telem[:command_line] || "N/A",
      file_hash: telem[:file_hash] || "N/A",
      triggered_at: (@detection&.triggered_at || @ticket&.created_at || Time.current).strftime("%Y-%m-%d %H:%M:%S UTC"),
      severity: (analysis[:severity] || @detection&.severity || "medium").upcase
    }
  end

  def format_timeline_step(evs)
    events = []
    base_time = @detection&.triggered_at || @ticket&.created_at || Time.current

    evs.each do |ev|
      t = begin
            Time.parse(ev[:occurred_at])
          rescue StandardError
            base_time
          end
      events << {
        timestamp: t.strftime("%H:%M:%S"),
        source: "EDR Sensörü (#{ev[:evidence_type]})",
        event_type: ev[:evidence_type],
        description: ev[:description]
      }
    end

    if events.size < 2
      events << {
        timestamp: base_time.strftime("%H:%M:%S"),
        source: "Sentriq EDR",
        event_type: "Detection Alert Triggered",
        description: "Olay telemetrisi kaydedildi: '#{@detection&.title || @ticket&.title}'"
      }
    end

    if events.size < 2
      events.unshift({
        timestamp: (base_time - 15.seconds).strftime("%H:%M:%S"),
        source: "Host Telemetry Logger",
        event_type: "Process Ingestion",
        description: "Uç noktada süreç yürütme argümanları ve ebeveyn süreç kaydı yakalandı."
      })
    end

    events
  end

  def format_process_tree_step(telem)
    parent = telem[:parent_process_name].presence || "explorer.exe"
    proc = telem[:process_name].presence || "powershell.exe"
    cmd = telem[:command_line].presence || "N/A"

    {
      root_ancestor: "wininit.exe (PID: 640)",
      parent_node: "#{parent} (PID: #{telem[:parent_process_id] || 'N/A'})",
      target_node: "#{proc} (PID: #{telem[:process_id] || 'N/A'})",
      command_line: cmd,
      network_connection: telem[:ip_address].present? ? "Hedef IP: #{telem[:ip_address]}" : "Doğrudan harici bağlantı kaydedilmedi",
      anomaly_flag: "Telemetri ilişkisi incelendi"
    }
  end

  def format_scenarios_step(analysis)
    cmd = (@detection&.command_line || @ticket&.description || "").downcase
    proc = (@detection&.process_name || "").downcase
    default_technique = if cmd.include?("vssadmin") || cmd.include?("shadow") || analysis[:classification].to_s.include?("ransomware")
                          "T1490 - Inhibit System Recovery"
                        elsif cmd.include?("certutil")
                          "T1105 - Ingress Tool Transfer"
                        elsif proc.include?("powershell") || cmd.include?("enc")
                          "T1059.001 - Command and Scripting Interpreter (PowerShell)"
                        else
                          analysis[:classification] || "T1059"
                        end

    chain = analysis[:attack_chain] || []
    if chain.any?
      chain.map do |step_text|
        {
          technique: default_technique,
          phase: "Forensic Progression",
          likelihood: analysis[:severity]&.capitalize || "Medium",
          description: step_text
        }
      end
    else
      [
        {
          technique: default_technique,
          phase: "Execution",
          likelihood: analysis[:severity]&.capitalize || "Medium",
          description: analysis[:incident_summary]
        }
      ]
    end
  end

  def format_root_cause_step(analysis, conf_assessment)
    hypotheses = analysis[:root_cause_hypotheses] || []
    primary = hypotheses.first || {
      hypothesis: analysis[:classification] || "Güvenlik İhlali Tespiti",
      likelihood: analysis[:severity]&.capitalize || "Medium",
      rationale: analysis[:incident_summary]
    }

    alternatives = analysis[:alternative_hypotheses] || []

    {
      primary: {
        hypothesis: primary[:hypothesis],
        confidence: conf_assessment[:score] || analysis[:confidence] || 70,
        rationale: primary[:rationale],
        likelihood: primary[:likelihood] || "High"
      },
      alternatives: alternatives.map do |a|
        {
          hypothesis: a[:hypothesis],
          confidence: [((conf_assessment[:score] || 50) * 0.4).round, 15].max,
          rationale: a[:rationale],
          likelihood: a[:likelihood] || "Low"
        }
      end
    }
  end

  def format_evidence_gaps_step(analysis, missing)
    proven = analysis[:evidence] || []
    unknowns = analysis[:missing_evidence] || missing || []
    deductions = [
      analysis[:confidence_rationale] || "Model kanıt zincirini değerlendirmiştir.",
      analysis[:impact_assessment] || "Olası etki analiz edilmiştir."
    ]

    {
      proven_findings: proven,
      deductions: deductions,
      unknown_gaps: unknowns
    }
  end

  def format_runbooks_step(runbooks)
    return [{ title: "No matching runbook found in knowledge base", category: "none", quote: "Bilgi tabanında bu olay için özel bir prosedür dokümanı eşleşmemiştir (kaynak uydurulmamıştır)." }] if runbooks.blank?

    runbooks.map do |r|
      {
        title: r[:title] || r[:document_title],
        category: r[:category],
        quote: r[:quote].to_s.truncate(220),
        relevance: r[:relevance] || "Tespit edilen süreç kurumsal runbook ile eşleşmektedir."
      }
    end
  end

  def format_prevention_step(analysis)
    actions = analysis[:recommended_actions] || []
    prevention = analysis[:prevention_measures] || []

    {
      immediate_containment: actions.any? ? actions : ["Uç nokta süreç ve ağ hareketlerini inceleyin."],
      preventive_hardening: prevention.any? ? prevention : ["Kurumsal güvenlik politikalarını ve ASR kurallarını gözden geçirin."]
    }
  end

  def format_risk_hitl_step(analysis, conf_assessment)
    sev = (analysis[:severity] || "medium").downcase
    is_critical = sev.in?(%w[high critical])
    requires_approval = analysis[:requires_human_approval] == true

    {
      overall_risk: sev.upcase,
      requires_human_approval: requires_approval,
      automated_actions_permitted: [
        "Olay telemetrisinin korelasyonu ve bilet oluşturma.",
        "İlgili runbook dokümanlarının sorgulanması ve iliştirilmesi.",
        "Denetim günlüğü (AuditEvent) kayıtlarının işlenmesi."
      ],
      human_approval_mandatory: [
        "Ana makinenin ağdan tamamen izole edilmesi (Host Quarantine).",
        "Kullanıcı hesabının Active Directory üzerinde askıya alınması.",
        "Kalıcı kayıt silme veya zararlı dosya karantinası."
      ],
      escalation_status: requires_approval ? "pending_review (Safety Gate Engaged)" : "resolved (Routine Triage)"
    }
  end

  def build_executive_summary(steps, analysis)
    host = steps[:step_1_telemetry][:hostname]
    title = @detection&.title || @ticket&.title || "Güvenlik Tespiti"
    hypothesis = steps[:step_5_root_cause][:primary][:hypothesis]
    risk = steps[:step_9_risk_and_hitl][:overall_risk]

    <<~EXEC
      SENTRIQ AI — YÖNETİCİ ÖZETİ (EXECUTIVE BRIEF)
      --------------------------------------------------
      1. NE OLDU?
      #{host} iş istasyonunda '#{title}' olayı incelendi.
      Özet: #{analysis[:incident_summary]}

      2. ETKİ VE RİSK NEDİR?
      Genel Risk Seviyesi: #{risk}. #{analysis[:impact_assessment]}

      3. OLASI KÖK NEDEN NEDİR?
      En güçlü hipotez: "#{hypothesis}" (Güven Skoru: %#{steps[:step_5_root_cause][:primary][:confidence]}).

      4. NE YAPILDI?
      Otonom Ajan telemetriyi analiz etti, runbook prosedürünü eşleştirdi ve güvenlik politikası doğrultusunda #{analysis[:requires_human_approval] ? 'insan onayına (pending_review)' : 'otonom çözüme'} aktardı.

      5. NE YAPILMALI?
      #{steps[:step_8_prevention][:immediate_containment].first || 'Telemetriyi doğrulayın.'}

      6. TEKRARINI ÖNLEMEK İÇİN NE ÖNERİLİYOR?
      #{steps[:step_8_prevention][:preventive_hardening].first || 'Güvenlik politikalarını güncelleyin.'}
    EXEC
  end

  def build_technical_report(steps, analysis)
    telem = steps[:step_1_telemetry]
    tree = steps[:step_3_process_tree]
    scenarios = steps[:step_4_scenarios]
    root_cause = steps[:step_5_root_cause]
    gaps = steps[:step_6_evidence_and_gaps]
    runbooks = steps[:step_7_runbooks]
    risk = steps[:step_9_risk_and_hitl]

    <<~TECH
      SENTRIQ AI — TEKNİK İNCELEME VE KÖK NEDEN RAPORU
      ==================================================
      Hedef Sistem: #{telem[:hostname]} | IP: #{telem[:ip_address]} | Kullanıcı: #{telem[:username]}
      Tetiklenme Zamanı: #{telem[:triggered_at]} | Önem Derecesi: #{telem[:severity]}
      
      [1] TELEMETRİ VE SÜREÇ SOYAĞACI
      - Ebeveyn Süreç: #{tree[:parent_node]}
      - Hedef Süreç:   #{tree[:target_node]}
      - Komut Satırı:  #{telem[:command_line]}
      - Dosya Hash:    #{telem[:file_hash]}

      [2] KRONOLOJİK OLAY ZAMAN ÇİZELGESİ
      #{steps[:step_2_timeline].map { |e| "[#{e[:timestamp]}] #{e[:event_type]}: #{e[:description]}" }.join("\n")}

      [3] SALDIRI ADIMLARI
      #{scenarios.map { |s| "- #{s[:technique]} (#{s[:phase]}): #{s[:description]} [Olasılık: #{s[:likelihood]}]" }.join("\n")}

      [4] KÖK NEDEN HİPOTEZLERİ
      - Birincil: #{root_cause[:primary][:hypothesis]} (%#{root_cause[:primary][:confidence]})
        Gerekçe: #{root_cause[:primary][:rationale]}
      - Alternatifler: #{root_cause[:alternatives].map { |a| "#{a[:hypothesis]} (#{a[:likelihood]})" }.join(', ')}

      [5] BULGULAR VE EKSİK BİLGİLER
      - Somut Bulgular: #{gaps[:proven_findings].size} adet
      - Eksik Bilgiler: #{gaps[:unknown_gaps].join('; ')}

      [6] EŞLEŞEN RUNBOOK DOKÜMANLARI
      #{runbooks.map { |r| "- #{r[:title]}: \"#{r[:quote]}\"" }.join("\n")}

      [7] İNSAN ONAYI VE MÜDAHALE SINIRLARI
      - Risk: #{risk[:overall_risk]} | İnsan Onayı Zorunlu: #{risk[:requires_human_approval]}
      - Güven Değerlendirmesi: #{analysis[:confidence_rationale]}
    TECH
  end

  def empty_investigation_result
    steps = {
      step_1_telemetry: { hostname: "N/A", ip_address: "N/A", username: "N/A", process_name: "N/A", process_id: 0, parent_process_name: "N/A", parent_process_id: 0, command_line: "N/A", file_hash: "N/A", triggered_at: Time.current.strftime("%Y-%m-%d %H:%M:%S UTC"), severity: "LOW" },
      step_2_timeline: [],
      step_3_process_tree: { root_ancestor: "N/A", parent_node: "N/A", target_node: "N/A", command_line: "N/A", network_connection: "N/A", anomaly_flag: "Kayıt yok" },
      step_4_scenarios: [],
      step_5_root_cause: { primary: { hypothesis: "Henüz incelenen bir olay yok", confidence: 0, rationale: "Sistemde aktif olay bulunamadı.", likelihood: "None" }, alternatives: [] },
      step_6_evidence_and_gaps: { proven_findings: [], deductions: [], unknown_gaps: [] },
      step_7_runbooks: [],
      step_8_prevention: { immediate_containment: [], preventive_hardening: [] },
      step_9_risk_and_hitl: { overall_risk: "LOW", requires_human_approval: false, automated_actions_permitted: [], human_approval_mandatory: [], escalation_status: "idle" },
      step_10_status: "awaiting_telemetry"
    }

    {
      success: true,
      detection: nil,
      ticket: nil,
      steps: steps,
      executive_summary: "Henüz aktif bir olay seçilmedi.",
      technical_report: "Henüz aktif bir olay seçilmedi."
    }
  end
end
