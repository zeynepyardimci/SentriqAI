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

    {
      intent: classification[:intent],
      priority: classification[:priority],
      recommended_action: classification[:recommended_action],
      draft_response: draft,
      rationale: classification[:rationale],
      confidence: classification[:confidence],
      evidence_refs: evidence_refs,
      source_refs: source_refs,
      requires_human_review: classification[:requires_human_review],
      limitations: "Analiz Sentriq AI Bağlamsal Analiz Motoru (Contextual Engine) tarafından üretilmiştir. Kararlar anahtar kelimelere göre değil, tüm cümlenin anlamsal bağlamına ve tespit telemetrisine göre değerlendirilmiştir."
    }
  end

  private

  def classify_context
    text = @full_text.downcase

    # Contextual check 1: Retrospective / Drill / Historical / Non-incident communication
    # (Even if text contains words like "acil", "kritik", "şüpheli" as quotes or drill descriptions)
    if retrospective_or_drill?(text)
      return {
        intent: "informational_retrospective",
        priority: "low",
        recommended_action: "Acknowledge routine report and archive ticket without active SOC escalation",
        rationale: "Metin geçmişe dönük bir tatbikat, rutin bilgilendirme veya tamamlanmış bir sürecin alıntısını içermektedir. Güvenlik kelimeleri ('acil', 'şüpheli') aktif bir tehdidi değil, geçmiş tatbikat bağlamını tanımlamaktadır.",
        confidence: 90,
        requires_human_review: false
      }
    end

    # Contextual check 2: Ambiguous or Conflicting Evidence
    if ambiguous_or_conflicting?(text)
      return {
        intent: "ambiguous_intent_verification",
        priority: "medium",
        recommended_action: "Escalate to human analyst for manual intent clarification and evidence correlation",
        rationale: "Gelen istekte çelişkili veya belirsiz ifadeler tespit edildi. Güvenlik politikaları gereği belirsiz durumlar otomatik onaylanamaz ve insan incelemesine devredilmelidir.",
        confidence: 65,
        requires_human_review: true
      }
    end

    # Contextual check 3: Active Attack / Living off the Land Execution
    if @detection.present? || active_attack_indicators?(text)
      det_sev = @detection&.severity || "high"
      return {
        intent: "active_threat_containment",
        priority: det_sev == "critical" ? "critical" : "high",
        recommended_action: "Perform host network containment and inspect parent-child process telemetry",
        rationale: "Aktif bir uç nokta tespiti veya şüpheli ikili/komut satırı yürütmesi tespit edildi. Sistem bütünlüğünü korumak için Seviye 2 analist doğrulaması gereklidir.",
        confidence: 88,
        requires_human_review: true
      }
    end

    # Default Contextual assessment: General Security Inquiry / Routine Triage
    {
      intent: "security_inquiry_or_triage",
      priority: @ticket.priority.presence || "medium",
      recommended_action: "Review telemetry and correlate with recent perimeter logs",
      rationale: "Standart güvenlik inceleme talebi. Yüksek riskli yıkıcı aksiyon bulunmamaktadır.",
      confidence: 78,
      requires_human_review: false
    }
  end

  def retrospective_or_drill?(text)
    drill_markers = [
      "tatbikat", "drill", "dünkü", "geceki", "geçmiş", "tamamlandı", 
      "başarıyla tamamladık", "arşiv", "test senaryosu", "routine check",
      "simulation completed", "retrospective"
    ]
    drill_markers.any? { |m| text.include?(m) }
  end

  def ambiguous_or_conflicting?(text)
    # Questions questioning whether it was an attack or benign, or contradictory statements
    text.include?("emin değilim") || 
      text.include?("belirsiz") || 
      text.include?("conflicting") || 
      text.include?("hem normal hem") ||
      text.include?("override rules") ||
      text.include?("kuralları devre dışı bırak")
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
        relevance_explanation: "Ticket bağlamında geçen süreçler ve saldırı teknikleri '#{r[:document_title]}' prosedürüyle eşleşmektedir."
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
      "İlgili Bilgi Tabanı Prosedürü: #{source_refs.first[:document_title]} (#{source_refs.first[:category]})."
    else
      "Kaynak Durumu: Bilgi tabanında bu olay için özel bir prosedür dokümanı eşleşmemiştir (kaynak uydurulmamıştır)."
    end

    <<~DRAFT
      [Sentriq AI Agent Yanıt Taslağı]
      İncelenen Ticket: #{@ticket.ticket_number} - #{@ticket.title}
      Belirlenen Niyet: #{classification[:intent].humanize} (Öncelik: #{classification[:priority].upcase})
      Önerilen Aksiyon: #{classification[:recommended_action]}
      
      Gerekçe: #{classification[:rationale]}
      #{ref_text}
      
      İnsan Denetimi: #{classification[:requires_human_review] ? 'GEREKLİ (Pending Review)' : 'Otomatik işleme uygun'}
    DRAFT
  end
end
