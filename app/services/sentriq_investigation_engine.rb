class SentriqInvestigationEngine
  def self.investigate(detection, rag_results = [])
    new(detection, rag_results).generate_report
  end

  def initialize(detection, rag_results = [])
    @detection = detection
    @evidences = detection.evidences.chronological
    @rag_results = rag_results
  end

  def generate_report
    observed = build_observed_evidence
    causes = evaluate_possible_causes
    gaps = identify_evidence_gaps
    steps = recommend_next_steps
    refs = build_source_references

    summary = generate_executive_summary(causes.first)

    {
      summary: summary,
      observed_evidence: observed,
      possible_causes: causes,
      evidence_gaps: gaps,
      recommended_steps: steps,
      source_references: refs,
      requires_human_review: true,
      confidence_score: calculate_confidence_score,
      limitations: "Bu rapor Sentriq AI Simüle Yerel Analiz Motoru tarafından üretilmiştir (harici API anahtarı yapılandırılmamıştır). Tüm bulgular sentetik telemetriye dayanır ve analist onayı zorunludur."
    }
  end

  private

  def build_observed_evidence
    list = []
    list << "Ana makine #{sanitize(@detection.hostname)} üzerinde '#{sanitize(@detection.process_name)}' (PID: #{@detection.process_id}) işlemi başlatıldı."

    if @detection.parent_process_name.present?
      list << "Ebeveyn süreç: '#{sanitize(@detection.parent_process_name)}' (PID: #{@detection.parent_process_id})."
    end

    if @detection.command_line.present?
      list << "Çalıştırılan komut satırı: '#{sanitize(@detection.command_line)}'."
    end

    if @detection.file_hash.present?
      list << "İkili dosya SHA256 özeti: #{@detection.file_hash}."
    end

    @evidences.each do |ev|
      list << "[#{ev.occurred_at.strftime('%H:%M:%S')}] #{ev.evidence_type.humanize}: #{sanitize(ev.description)}"
    end

    list
  end

  def evaluate_possible_causes
    cmd = @detection.command_line.to_s.downcase
    proc = @detection.process_name.to_s.downcase

    causes = []

    if cmd.include?("encodedcommand") || cmd.include?("-enc") || cmd.include?("downloadstring")
      causes << {
        hypothesis: "Obfuscated PowerShell Execution (T1059.001)",
        likelihood: "High",
        rationale: "Komut satırında Base64 kodlanmış veya uzaktan betik indirme parametreleri tespit edildi. Bu davranış tespit mekanizmalarını atlatmak için yaygın olarak kullanılır."
      }
    elsif cmd.include?("certutil") && cmd.include?("urlcache")
      causes << {
        hypothesis: "Living off the Land Binary (LOLBin) Ingress Tool (T1105)",
        likelihood: "High",
        rationale: "CertUtil yardımcı programının sertifika doğrulama yerine harici bir kaynaktan dosya indirmek amacıyla kullanıldığı gözlemlendi."
      }
    elsif cmd.include?("vssadmin") && cmd.include?("delete")
      causes << {
        hypothesis: "Inhibit System Recovery (T1490)",
        likelihood: "Critical",
        rationale: "Gölge kopyaları silme komutu fidye yazılımı (ransomware) öncesi sistem geri yüklemeyi engelleme aşamasıyla uyuşmaktadır."
      }
    elsif proc.include?("mimikatz") || cmd.include?("sekurlsa")
      causes << {
        hypothesis: "OS Credential Dumping (T1003)",
        likelihood: "Critical",
        rationale: "LSASS bellek alanına yetkisiz erişim ve kimlik bilgisi çalma girişimiyle ilişkili parametreler gözlemlendi."
      }
    else
      causes << {
        hypothesis: "Şüpheli Süreç Davranışı ve Beklenmeyen Alt Süreç Başlatma",
        likelihood: "Medium",
        rationale: "Normal iş istasyonu profilinin dışında bir ebeveyn-çocuk işlem ilişkisi ve ağ etkinliği kaydedildi."
      }
    end

    # Alternate hypothesis (false positive possibility)
    causes << {
      hypothesis: "Meşru Sistem Yönetim Betiği veya Güncelleme Görevi",
      likelihood: "Low",
      rationale: "Yetkili BT personeli tarafından zamanlanmış bakım veya dağıtım otomasyonunun çalıştırılmış olma ihtimali incelenmelidir."
    }

    causes
  end

  def identify_evidence_gaps
    gaps = []
    gaps << "Uç noktada bellek dökümü (memory dump) veya ETW (Event Tracing for Windows) logları henüz incelenmedi."
    gaps << "Ebeveyn sürecin tetiklendiği ilk oturum açma (Logon Type 10 vs Type 3) kayıtları korele edilmedi."
    gaps << "İlgili dosya özetinin (hash) kurum içi diğer uç noktalardaki yaygınlık (prevalence) verisi eksik."
    gaps
  end

  def recommend_next_steps
    steps = []
    steps << "Etkilenen ana makinenin (#{sanitize(@detection.hostname)}) ağ izolasyonu (containment) değerlendirilmelidir."
    steps << "Kullanıcı hesabının (#{sanitize(@detection.username || 'N/A')}) son 24 saatlik kimlik doğrulama kayıtları kontrol edilmelidir."
    steps << "İlişkili IP adresleri ve etki alanları şirket güvenlik duvarı ve DNS filtreleme kayıtlarında sorgulanmalıdır."
    steps << "Bulgular Seviye 2 analist veya Olay Müdahale liderinin onayına sunulmalıdır."
    steps
  end

  def build_source_references
    return [] if @rag_results.blank?

    @rag_results.map do |item|
      {
        document_id: item[:document_id],
        document_title: item[:document_title],
        category: item[:category],
        quote: item[:quote].to_s.truncate(300),
        relevance_explanation: "Tespit edilen '#{@detection.process_name}' ve ilgili parametreler ile '#{item[:document_title]}' prosedürü eşleşmektedir.",
        chunk_index: item[:chunk_index]
      }
    end
  end

  def generate_executive_summary(primary_cause)
    cause_name = primary_cause ? primary_cause[:hypothesis] : "Şüpheli Olay"
    "Sentriq AI araştırması: #{@detection.hostname} üzerinde tetiklenen '#{@detection.title}' tespiti incelendi. " \
    "Toplanan #{@evidences.count + 1} kanıt öğesi değerlendirildiğinde olası ana etken '#{cause_name}' olarak belirlenmiştir. " \
    "Bu bulgu analist denetimi gerektirir; nihai aksiyon için insan onayı beklenmektedir."
  end

  def calculate_confidence_score
    score = 70
    score += 10 if @evidences.any?
    score += 10 if @rag_results.any?
    score += 5 if @detection.file_hash.present?
    [score, 95].min
  end

  def sanitize(text)
    ERB::Util.html_escape(text.to_s)
  end
end
