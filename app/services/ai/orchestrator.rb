# frozen_string_literal: true

module Ai
  class Orchestrator
    def self.call(ticket: nil, detection: nil, current_user: nil, force_reanalyze: false, force_refresh: false)
      new(
        ticket: ticket,
        detection: detection,
        current_user: current_user,
        force_reanalyze: force_reanalyze || force_refresh
      ).call
    end

    class << self
      alias_method :analyze, :call
    end

    def initialize(ticket: nil, detection: nil, current_user: nil, force_reanalyze: false, force_refresh: false)
      @ticket = ticket.is_a?(Ticket) ? ticket : (Ticket.find_by(id: ticket) if ticket.present?)
      @detection = detection.is_a?(Detection) ? detection : (Detection.find_by(id: detection) if detection.present?)
      @detection ||= @ticket&.detection
      @ticket ||= @detection&.tickets&.recent_first&.first
      @current_user = current_user
      @force_reanalyze = force_reanalyze || force_refresh
    end

    def call
      # 1. Validate target existence or build fallback empty state
      unless @ticket || @detection
        return empty_orchestration_result("İncelenecek bir olay veya bilet seçilmedi.")
      end

      # 2. Build Event Context
      context = IncidentContextBuilder.new(
        ticket: @ticket,
        detection: @detection,
        current_user: @current_user
      ).build

      context_hash = context[:context_hash]
      cache_key = "sentriq_ai_analysis_#{@ticket&.id || 'det'}_#{@detection&.id}_#{context_hash}"

      # Check cache if not forcing reanalysis
      if !@force_reanalyze && (cached = Rails.cache.read(cache_key))
        Rails.logger.info("[Ai::Orchestrator] Cache hit for incident #{cache_key}")
        cached_result = cached.deep_dup
        cached_result[:from_cache] = true
        cached_result[:cached] = true
        return cached_result.with_indifferent_access
      end

      # 3. Retrieve Grounded Runbooks via RAG
      runbook_result = RunbookRetriever.retrieve(context, limit: 3, current_user: @current_user)

      # 4. Analyze via LLM or Deterministic Engine
      raw_analysis = IncidentAnalyzer.analyze(context, runbook_result: runbook_result)
      agent_mode = raw_analysis[:agent_mode] || "deterministic_local_engine"

      # 5. Validate Output Schema
      validated = AnalysisSchemaValidator.validate(raw_analysis)
      validated[:context_hash] = context_hash

      # 6. Evaluate Dynamic Confidence & Evidence Quality
      is_conflicting = context[:incident_type] == :ambiguous_or_conflicting
      confidence_assessment = ConfidenceEvaluator.evaluate(
        context,
        model_confidence: validated[:confidence],
        model_rationale: validated[:confidence_rationale],
        is_conflicting: is_conflicting
      )

      # Enrich analysis with dual confidence assessment
      validated[:confidence] = confidence_assessment[:score]
      validated[:confidence_assessment] = confidence_assessment
      validated[:confidence_rationale] = confidence_assessment[:basis]
      validated[:missing_evidence] = confidence_assessment[:missing_evidence]

      # 7. Persist Result to DB
      AnalysisPersistenceService.persist(
        ticket: @ticket,
        detection: @detection,
        validated_analysis: validated,
        current_user: @current_user,
        agent_mode: agent_mode
      )

      # 8. Prepare Structured Result Payload
      result = {
        success: true,
        ticket: @ticket,
        detection: @detection,
        context: context,
        analysis: validated,
        agent_mode: agent_mode,
        runbook_matches: runbook_result[:runbooks],
        confidence_assessment: confidence_assessment,
        cached: false,
        from_cache: false
      }.with_indifferent_access

      # Write to cache with 15-minute TTL
      Rails.cache.write(cache_key, result, expires_in: 15.minutes)

      result
    rescue StandardError => e
      Rails.logger.error("[Ai::Orchestrator] Orchestration failed: #{e.message}\n#{e.backtrace.first(5).join("\n")}")
      empty_orchestration_result("Analiz sırasında hata oluştu: #{e.message}")
    end

    private

    def empty_orchestration_result(message)
      fallback_analysis = AnalysisSchemaValidator.validate({
        incident_summary: message,
        classification: "unassigned",
        severity: "low",
        confidence: 0,
        confidence_rationale: "Aktif olay bulunamadı.",
        evidence: [],
        missing_evidence: [],
        root_cause_hypotheses: [],
        alternative_hypotheses: [],
        attack_chain: [],
        impact_assessment: "N/A",
        matched_runbooks: [],
        recommended_actions: ["Lütfen bir bilet veya olay seçin."],
        prevention_measures: [],
        requires_human_approval: false,
        analysis_limitations: "Veri yok"
      })

      {
        success: false,
        ticket: nil,
        detection: nil,
        context: {},
        analysis: fallback_analysis,
        agent_mode: "fallback",
        runbook_matches: [],
        confidence_assessment: {
          score: 0,
          evidence_quality: 0,
          model_confidence: 0,
          basis: message,
          missing_evidence: [],
          calibration_status: "not_available"
        },
        error: message
      }.with_indifferent_access
    end
  end
end
