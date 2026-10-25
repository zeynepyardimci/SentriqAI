# frozen_string_literal: true

module Ai
  class ConfidenceEvaluator
    def self.evaluate(context, model_confidence: nil, model_rationale: nil, is_conflicting: false)
      new(context, model_confidence: model_confidence, model_rationale: model_rationale, is_conflicting: is_conflicting).evaluate
    end

    def initialize(context, model_confidence: nil, model_rationale: nil, is_conflicting: false)
      @context = context
      @raw_model_confidence = model_confidence
      @model_rationale = model_rationale
      @is_conflicting = is_conflicting
    end

    def evaluate
      evidence_quality_score, quality_factors = calculate_evidence_quality
      sanitized_model_confidence = sanitize_model_confidence(@raw_model_confidence)

      composite_score, score_basis = calculate_composite_score(
        evidence_quality: evidence_quality_score,
        model_confidence: sanitized_model_confidence,
        quality_factors: quality_factors
      )

      missing_evidence_list = @context[:missing_fields] || []

      {
        score: composite_score,
        evidence_quality: evidence_quality_score,
        model_confidence: sanitized_model_confidence,
        basis: score_basis,
        missing_evidence: missing_evidence_list,
        quality_factors: quality_factors,
        calibration_status: "uncalibrated_heuristic",
        calibration_disclaimer: "Bu güven skoru istatistiksel bir saldırı olasılığı değildir. Telemetri zenginliği ve model sezgisinin şeffaf bileşkesidir."
      }
    end

    private

    def calculate_evidence_quality
      telem = @context[:telemetry] || {}
      evs = @context[:evidences] || []
      missing = @context[:missing_fields] || []
      archetype = @context[:incident_type]

      quality = 20 # Temel başlangıç
      factors = []

      # 1. Somut süreç ve komut satırı
      if telem[:process_name].present?
        quality += 12
        factors << "+12: Çalıştırılan süreç adı EDR tarafından doğrulandı (#{telem[:process_name]})"
      else
        factors << "-10: Süreç adı telemetride eksik"
      end

      if telem[:command_line].present?
        quality += 15
        factors << "+15: Tam komut satırı argümanları mevcut"
      else
        factors << "-15: Komut satırı argümanı bulunamadı"
      end

      # 2. Ebeveyn süreç soyağacı
      if telem[:parent_process_name].present?
        quality += 10
        factors << "+10: Ebeveyn süreç (#{telem[:parent_process_name]}) ilişkisi tespit edildi"
      end

      # 3. Kriptografik dosya özeti
      if telem[:file_hash].present?
        quality += 12
        factors << "+12: İkili dosya SHA256 özeti mevcut"
      else
        factors << "-8: Dosya hash'i eksik"
      end

      # 4. Korelasyonlu olay sayısı (evidences)
      if evs.any?
        count_bonus = [evs.size * 4, 16].min
        quality += count_bonus
        factors << "+#{count_bonus}: #{evs.size} adet korelasyonlu olay zinciri kaydedildi"
      end

      # 5. Ağ veya dosya faaliyeti
      has_network = evs.any? { |e| e[:evidence_type].to_s.include?("network") }
      if has_network || telem[:ip_address].present?
        quality += 8
        factors << "+8: Ağ telemetrisi / IP bağlantısı mevcut"
      end

      # 6. Çelişki veya belirsizlik cezası
      if @is_conflicting || archetype == :ambiguous_or_conflicting
        quality -= 20
        factors << "-20: Çelişkili veya belirsiz ifadeler tespit edildi"
      end

      # 7. Eksik alan cezası
      if missing.size >= 4
        quality -= 12
        factors << "-12: Kritik telemetri alanlarında yüksek eksiklik (#{missing.join(', ')})"
      end

      clamped_quality = [[quality, 95].min, 15].max
      [clamped_quality, factors]
    end

    def sanitize_model_confidence(raw)
      return nil if raw.blank?
      num = raw.to_f
      num = (num * 100).round if num <= 1.0 && num > 0
      clamped = [[num.round, 98].min, 10].max
      clamped
    end

    def calculate_composite_score(evidence_quality:, model_confidence:, quality_factors:)
      if model_confidence.present?
        # Ağırlıklı kombinasyon: %60 Kanıt Kalitesi + %40 Model Güveni
        composite = ((evidence_quality * 0.60) + (model_confidence * 0.40)).round
        basis = "Skor: %60 Kanıt Kalitesi (#{evidence_quality}) + %40 Model Değerlendirmesi (#{model_confidence}). Faktörler: #{quality_factors.join('; ')}."
      else
        composite = evidence_quality
        basis = "Skor doğrudan Kanıt Kalitesi endeksinden hesaplandı (#{evidence_quality}). Faktörler: #{quality_factors.join('; ')}."
      end

      # Operational confidence bound: non-conflicting telemetry stays in 40..95 range
      composite = [[composite, 95].min, 40].max unless @is_conflicting

      [composite, basis]
    end
  end
end
