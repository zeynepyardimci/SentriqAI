# frozen_string_literal: true

module Ai
  class AnalysisSchemaValidator
    SEVERITIES = %w[low medium high critical].freeze

    REQUIRED_FIELDS = %i[
      incident_summary
      classification
      severity
      confidence
      confidence_rationale
      evidence
      missing_evidence
      root_cause_hypotheses
      alternative_hypotheses
      attack_chain
      impact_assessment
      matched_runbooks
      recommended_actions
      prevention_measures
      requires_human_approval
      analysis_limitations
    ].freeze

    def self.validate(payload)
      new(payload).validate
    end

    def initialize(payload)
      @raw = payload.is_a?(Hash) ? payload.with_indifferent_access : {}
    end

    def validate
      errors = []
      validated = {}

      # 1. Strings
      validated[:incident_summary] = sanitize_string(@raw[:incident_summary], fallback: "Olay telemetrisi ve kanıt zinciri incelendi.")
      validated[:classification] = sanitize_string(@raw[:classification] || @raw[:intent], fallback: "security_incident_triage")

      # 2. Severity
      raw_sev = @raw[:severity].to_s.downcase.strip
      validated[:severity] = SEVERITIES.include?(raw_sev) ? raw_sev : "medium"

      # 3. Confidence (0-100)
      raw_conf = @raw[:confidence]
      validated[:confidence] = sanitize_integer(raw_conf, min: 0, max: 100, fallback: 50)
      validated[:confidence_rationale] = sanitize_string(@raw[:confidence_rationale], fallback: "Telemetri doluluğu ve model sınıflandırmasına göre hesaplandı.")

      # 4. Arrays
      validated[:evidence] = sanitize_array(@raw[:evidence])
      validated[:missing_evidence] = sanitize_array(@raw[:missing_evidence])
      validated[:attack_chain] = sanitize_array(@raw[:attack_chain])
      validated[:recommended_actions] = sanitize_array(@raw[:recommended_actions])
      validated[:prevention_measures] = sanitize_array(@raw[:prevention_measures])
      validated[:matched_runbooks] = sanitize_array_of_hashes(@raw[:matched_runbooks])

      # 5. Hypotheses
      validated[:root_cause_hypotheses] = sanitize_hypotheses(@raw[:root_cause_hypotheses])
      validated[:alternative_hypotheses] = sanitize_hypotheses(@raw[:alternative_hypotheses])

      # 6. Text assessments
      validated[:impact_assessment] = sanitize_string(@raw[:impact_assessment], fallback: "Etki analizi telemetri sınırları dahilinde değerlendirildi.")
      validated[:analysis_limitations] = sanitize_string(@raw[:analysis_limitations], fallback: "Analiz Sentriq AI tarafından üretilmiştir. Bulgular insan denetimine tabidir.")

      # 7. Boolean HITL
      raw_hitl = @raw[:requires_human_approval]
      validated[:requires_human_approval] = if validated[:severity].in?(%w[high critical])
                                              true
                                            elsif raw_hitl.nil?
                                              true
                                            else
                                              ActiveModel::Type::Boolean.new.cast(raw_hitl)
                                            end

      # Backward-compatible mappings
      validated[:intent] = @raw[:intent] || @raw["intent"] || validated[:classification]
      validated[:priority] = validated[:severity]
      validated[:draft_response] = @raw[:draft_response] || build_default_draft(validated)
      validated[:rationale] = @raw[:reasoning] || @raw[:rationale] || validated[:confidence_rationale]
      validated[:reasoning] = @raw[:reasoning] || validated[:incident_summary]
      validated[:recommended_action] = @raw[:recommended_action] || validated[:recommended_actions]&.first || "Host isolation review"
      validated[:matched_runbook] = validated[:matched_runbooks]&.first&.dig(:title) || "No matching runbook found in knowledge base"
      validated[:source_refs] = validated[:matched_runbooks] || []
      validated[:confidence_note] = @raw[:confidence_note] || "Model heuristic confidence score; not an actuarial probability."
      validated[:requires_human_review] = validated[:requires_human_approval]
      validated[:confidence_assessment] = @raw[:confidence_assessment] || {}

      validated
    end

    private

    def sanitize_string(val, fallback:)
      str = val.to_s.strip
      str.present? ? str : fallback
    end

    def sanitize_integer(val, min:, max:, fallback:)
      return fallback if val.blank?
      num = val.to_f
      num = (num * 100).round if num <= 1.0 && num > 0
      int_val = num.round
      [[int_val, max].min, min].max
    rescue StandardError
      fallback
    end

    def sanitize_array(val)
      return [] if val.blank?
      Array(val).map(&:to_s).map(&:strip).reject(&:blank?)
    end

    def sanitize_array_of_hashes(val)
      return [] if val.blank?
      Array(val).map do |item|
        if item.is_a?(Hash)
          item.symbolize_keys
        else
          { title: item.to_s }
        end
      end
    end

    def sanitize_hypotheses(val)
      return [] if val.blank?
      Array(val).map do |h|
        if h.is_a?(Hash)
          {
            hypothesis: h[:hypothesis] || h["hypothesis"] || "Bilinmeyen hipotez",
            likelihood: h[:likelihood] || h["likelihood"] || "Medium",
            rationale: h[:rationale] || h["rationale"] || "Detaylı gerekçe analist tarafından incelenmelidir."
          }
        else
          {
            hypothesis: h.to_s,
            likelihood: "Medium",
            rationale: "Model çıkarımı"
          }
        end
      end
    end

    def build_default_draft(data)
      "[Sentriq AI Güvenlik Olayı Triyaj Raporu]\n" \
      "Özet: #{data[:incident_summary]}\n" \
      "Sınıflandırma: #{data[:classification]} (Önem: #{data[:severity].upcase})\n" \
      "Güven Skoru: %#{data[:confidence]}\n" \
      "Önerilen Müdahale: #{data[:recommended_actions].first || 'Telemetriyi incele'}\n" \
      "İnsan Onayı: #{data[:requires_human_approval] ? 'ZORUNLU (Pending Review)' : 'Rutin/Otomasyona Uygun'}"
    end
  end
end
