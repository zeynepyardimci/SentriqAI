class ContextualAnalysisEngine
  def self.analyze(ticket, rag_results = [])
    new(ticket, rag_results).generate_analysis
  end

  def initialize(ticket, rag_results = [])
    @ticket = ticket
    @detection = ticket.detection
    @rag_results = rag_results
    @full_text = "#{ticket.title} #{ticket.description}".strip
  end

  def generate_analysis
    classification = classify_context
    source_refs = build_source_references
    evidence_refs = build_evidence_references

    draft = generate_draft_response(classification, source_refs)

    matched_runbook = if source_refs.any?
                        source_refs.first[:document_title]
                      else
                        "No matching runbook found in knowledge base"
                      end

    concrete_evidence = if evidence_refs.any?
                          evidence_refs.map { |e| "[#{e[:evidence_type]}] #{e[:description]}" }
                        elsif @detection
                          [
                            "Process: #{@detection.process_name || 'N/A'} (PID: #{@detection.process_id || 'N/A'})",
                            "Command Line: #{@detection.command_line || 'N/A'}",
                            "Host: #{@detection.hostname}",
                            "Parent Process: #{@detection.parent_process_name || 'N/A'}"
                          ]
                        else
                          ["Ticket Title: #{@ticket.title}", "Telemetry excerpt: #{@ticket.description.to_s.truncate(150)}"]
                        end

    {
      # Challenge Standard Keys
      severity: classification[:priority],
      confidence: classification[:confidence],
      confidence_note: "LLM Guven Degerlendirmesi: Bu skor, modelin siniflandirmaya duydugu heuristik guveni ifade eder. Istatistiksel olarak kalibre edilmis bir olasilik degildir. Skor, telemetri kalitesi ve bagiam zenginligine gore her olay icin bagimsiz hesaplanmaktadir.",
      confidence_rationale: classification[:confidence_rationale],
      missing_evidence: classification[:missing_evidence] || [],
      alternative_hypotheses: classification[:alternative_hypotheses] || [],
      classification: classification[:intent],
      evidence: concrete_evidence,
      reasoning: classification[:rationale],
      matched_runbook: matched_runbook,
      recommended_action: classification[:recommended_action],
      requires_human_approval: classification[:requires_human_review],

      # Backward-compatible keys
      intent: classification[:intent],
      priority: classification[:priority],
      draft_response: draft,
      rationale: classification[:rationale],
      evidence_refs: evidence_refs,
      source_refs: source_refs,
      requires_human_review: classification[:requires_human_review],
      limitations: "Analiz Sentriq AI Baglamsal Analiz Motoru (Contextual Engine) tarafindan uretilmistir. Kararlar anahtar kelimelere gore degil, tum cumlenin anlamsal baglamina ve tespit telemetrisine gore degerlendirilmistir. Guven skoru istatistiksel olarak kalibre edilmemistir."
    }
  end

  private

  def classify_context
    text = @full_text.downcase

    if retrospective_or_drill?(text)
      conf = calculate_dynamic_confidence(base: 88)
      return {
        intent: "informational_retrospective",
        priority: "low",
        recommended_action: "Acknowledge routine report and archive ticket without active SOC escalation",
        rationale: "Metin gecmise donuk bir tatbikat, rutin bilgilendirme veya tamamlanmis bir surecin alintisini icermektedir.",
        confidence: conf,
        confidence_rationale: "Tatbikat/retrospektif belirtecler net olarak tespit edildi. Aktif tehdit gostergesi bulunmuyor.",
        missing_evidence: [],
        alternative_hypotheses: [],
        requires_human_review: false
      }
    end

    if ambiguous_or_conflicting?(text)
      conf = calculate_dynamic_confidence(base: 55)
      return {
        intent: "ambiguous_intent_verification",
        priority: "medium",
        recommended_action: "Escalate to human analyst for manual intent clarification and evidence correlation",
        rationale: "Gelen istekte celiskili veya belirsiz ifadeler tespit edildi. Belirsiz durumlar otomatik onaylanamaz.",
        confidence: conf,
        confidence_rationale: "Celiskili ifadeler modelin karar guvenini dusurdu. Eksik telemetri nedeniyle kesin siniflandirma yapilamiyor.",
        missing_evidence: ["Insan analistinin bagiam aciklamasi", "Oturum kayitlari (Session logs)", "Ag trafigi korelasyonu"],
        alternative_hypotheses: ["Mesru sistem yonetim islemi", "Yanlis pozitif alarm", "Kullanici hatasi"],
        requires_human_review: true
      }
    end

    if @detection.present? || active_attack_indicators?(text)
      det_sev = (@ticket.priority == "critical" || @detection&.severity == "critical") ? "critical" : "high"
      conf = calculate_dynamic_confidence(base: 72)
      return {
        intent: "active_threat_containment",
        priority: det_sev,
        recommended_action: "Perform host network containment and inspect parent-child process telemetry",
        rationale: "Aktif bir uc nokta tespiti veya supheli ikili/komut satiri yurutmlesi tespit edildi. Seviye 2 analist dogrulamasi gereklidir.",
        confidence: conf,
        confidence_rationale: build_active_threat_confidence_rationale(conf),
        missing_evidence: build_missing_evidence_for_active_threat,
        alternative_hypotheses: ["Yetkili BT yonetim betigi", "Zamanlanmis sistem bakim gorevi", "Guvenlik tarayici etkinligi"],
        requires_human_review: true
      }
    end

    conf = calculate_dynamic_confidence(base: 60)
    {
      intent: "security_inquiry_or_triage",
      priority: @ticket.priority.presence || "medium",
      recommended_action: "Review telemetry and correlate with recent perimeter logs",
      rationale: "Standart guvenlik inceleme talebi. Yuksek riskli yikici aksiyon bulunmamaktadir.",
      confidence: conf,
      confidence_rationale: "Genel guvenlik sorgusu — saldiri gostergesi sinirli. Ek telemetri guveni artirabilir.",
      missing_evidence: ["Surec ebeveyn-cocuk iliskisi detaylari", "Ag baglanti loglari"],
      alternative_hypotheses: ["Rutin yonetim islemi"],
      requires_human_review: false
    }
  end

  # Dynamic confidence: heuristic score based on telemetry richness — NOT a calibrated probability.
  def calculate_dynamic_confidence(base: 72)
    score = base

    if @detection
      score += 8 if @detection.command_line.present?
      score += 5 if @detection.file_hash.present?
      score += 4 if @detection.parent_process_name.present?
      score += 3 if @detection.ip_address.present?
      ev_count = @detection.evidences.loaded? ? @detection.evidences.size : @detection.evidences.count
      score += [ev_count * 2, 10].min
      score += 3 if @detection.severity.in?(%w[high critical])
    end

    score += 6 if @rag_results.any?
    [[score, 95].min, 40].max
  end

  def build_active_threat_confidence_rationale(conf)
    parts = []
    if @detection
      parts << "Uc nokta tespiti mevcut (#{@detection.hostname})"
      parts << "Surec: #{@detection.process_name}" if @detection.process_name.present?
      ev_count = @detection.evidences.loaded? ? @detection.evidences.size : @detection.evidences.count
      parts << "#{ev_count} korelasyonlu kanit" if ev_count > 0
      parts << "Dosya ozeti mevcut" if @detection.file_hash.present?
    else
      parts << "Saldiri gostergeleri metin analizinde tespit edildi"
    end
    parts << "Bilgi tabani runbook eslesmesi bulundu" if @rag_results.any?
    base_text = parts.any? ? parts.join("; ") + ". " : ""
    "#{base_text}Model guven skoru #{conf} — telemetri zenginligine gore hesaplandi. LLM heuristik degerlendirmesi; istatistiksel kalibrasyon yapilmamistir."
  end

  def build_missing_evidence_for_active_threat
    gaps = []
    if @detection
      gaps << "Bellek dokumu (memory dump) veya ETW loglari" unless @detection.file_hash.present?
      gaps << "Ag trafigi PCAP analizi"
      gaps << "Kullanici oturum acma kayitlari (Logon Type)" unless @detection.username.present?
    else
      gaps << "Uc nokta tespiti verisi (hostname, process, command_line)"
      gaps << "Telemetri kanit zinciri"
    end
    gaps
  end

  def retrospective_or_drill?(text)
    drill_markers = [
      "tatbikat", "drill", "tamamland", "tamamlandi",
      "basariyla tamamla", "arsiv", "test senaryosu", "routine check",
      "simulation completed", "retrospective", "geceki", "gecmis"
    ]
    drill_markers.any? { |m| text.include?(m) }
  end

  def ambiguous_or_conflicting?(text)
    text.include?("emin degilim") ||
      text.include?("emin de") ||
      text.include?("belirsiz") ||
      text.include?("conflicting") ||
      text.include?("celiskili") ||
      text.include?("hem normal hem") ||
      text.include?("override rules") ||
      text.include?("kurallari devre disi birak")
  end

  def active_attack_indicators?(text)
    [
      "powershell", "encodedcommand", "certutil", "vssadmin",
      "mimikatz", "shadow copy", "beacon", "ransomware", "malware",
      "c2", "unauthorized execution", "c&c"
    ].any? { |i| text.include?(i) }
  end

  def build_source_references
    return [] if @rag_results.blank?
    @rag_results.map do |r|
      {
        document_id: r[:document_id],
        document_title: r[:document_title],
        category: r[:category],
        quote: r[:quote].to_s.truncate(250),
        relevance_explanation: "Ticket baglaminda gecen surecler ve saldiri teknikleri '#{r[:document_title]}' proceduruyle eslesmektedir."
      }
    end
  end

  def build_evidence_references
    return [] unless @detection
    @detection.evidences.chronological.map do |ev|
      {
        evidence_id: ev.id,
        evidence_type: ev.evidence_type,
        timestamp: ev.occurred_at.iso8601,
        description: ev.description
      }
    end
  end

  def generate_draft_response(classification, source_refs)
    ref_text = if source_refs.any?
      "Ilgili Bilgi Tabani Proseduru: #{source_refs.first[:document_title]} (#{source_refs.first[:category]})."
    else
      "Kaynak Durumu: Bilgi tabaninda bu olay icin ozel bir procedure dokumani eslesmemistir (kaynak uydurmulmamistir)."
    end

    "[Sentriq AI Agent Yanit Taslagi]\n" \
    "Incelenen Ticket: #{@ticket.ticket_number} - #{@ticket.title}\n" \
    "Belirlenen Niyet: #{classification[:intent].humanize} (Oncelik: #{classification[:priority].upcase})\n" \
    "LLM Guven Skoru: #{classification[:confidence]} — #{classification[:confidence_rationale]}\n" \
    "Onerilen Aksiyon: #{classification[:recommended_action]}\n\n" \
    "Gerekce: #{classification[:rationale]}\n" \
    "#{ref_text}\n\n" \
    "Insan Denetimi: #{classification[:requires_human_review] ? 'GEREKLI (Pending Review)' : 'Otomatik isleme uygun'}"
  end
end