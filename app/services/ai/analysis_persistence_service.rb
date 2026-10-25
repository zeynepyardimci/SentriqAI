# frozen_string_literal: true

module Ai
  class AnalysisPersistenceService
    def self.persist(ticket: nil, detection: nil, validated_analysis:, current_user: nil, agent_mode: "deterministic_local_engine")
      new(
        ticket: ticket,
        detection: detection,
        validated_analysis: validated_analysis,
        current_user: current_user,
        agent_mode: agent_mode
      ).persist
    end

    def initialize(ticket:, detection:, validated_analysis:, current_user: nil, agent_mode: "deterministic_local_engine")
      @ticket = ticket
      @detection = detection
      @analysis = validated_analysis
      @current_user = current_user
      @agent_mode = agent_mode
    end

    def persist
      ActiveRecord::Base.transaction do
        # 1. Update Ticket if present
        if @ticket.present?
          existing_analysis = @ticket.llm_analysis || {}
          merged_analysis = existing_analysis.merge(@analysis.stringify_keys)
          merged_analysis["agent_mode"] = @agent_mode
          merged_analysis["last_analyzed_at"] = Time.current.iso8601

          target_priority = @analysis[:severity].presence || @ticket.priority

          @ticket.update_columns(
            llm_analysis: merged_analysis,
            priority: target_priority,
            agent_mode: @agent_mode,
            updated_at: Time.current
          )

          # Add note if not already noted recently
          create_ticket_note!

          # Escalate to human review if analysis requires human confirmation
          if @analysis[:requires_human_approval] && @ticket.status == "open" && @ticket.can_transition_to?("pending_review")
            @ticket.escalate_to_human!(
              reason: "LLM contextual analysis flagged ticket for human review: #{@analysis[:incident_summary]} (Gerekçe: #{@analysis[:confidence_rationale]})",
              user: @current_user
            )
          end
          # Note: Analysis completion != ticket resolution. Ticket remains in its legitimate state (e.g. open/pending_review)
          # until verified action execution or analyst approval.

          record_audit_event!(@ticket, "ticket_ai_orchestrated_analysis")
        end

        # 2. Persist Investigation record for Detection if detection present
        if @detection.present?
          persist_investigation_record!
          record_audit_event!(@detection, "detection_ai_orchestrated_analysis")
        end
      end

      true
    rescue StandardError => e
      Rails.logger.error("[SentriqAI::AnalysisPersistenceService] Persistence failed: #{e.message}\n#{e.backtrace.first(5).join("\n")}")
      false
    end

    private

    def create_ticket_note!
      primary_cause = @analysis[:root_cause_hypotheses]&.first&.dig(:hypothesis) || "Güvenlik İncelemesi"

      note_body = "[Sentriq AI Orchestrator Analiz Raporu]\n" \
                  "• Özet: #{@analysis[:incident_summary]}\n" \
                  "• Sınıflandırma: #{@analysis[:classification]} (Önem: #{@analysis[:severity].upcase})\n" \
                  "• Güven Skoru: %#{@analysis[:confidence]} — #{@analysis[:confidence_rationale]}\n" \
                  "• Olası Kök Neden: #{primary_cause}\n" \
                  "• Önerilen Eylem: #{@analysis[:recommended_actions]&.first || 'Telemetriyi inceleyin'}\n" \
                  "• İnsan Onayı: #{@analysis[:requires_human_approval] ? 'ZORUNLU (Pending Review)' : 'Rutin/Otomasyona Uygun'}"

      @ticket.ticket_notes.create!(
        user: @current_user,
        author_type: "agent",
        author_name: @ticket.assigned_agent.presence || "Sentriq-AI-Orchestrator",
        note_type: "analysis_draft",
        body: note_body,
        metadata: {
          confidence: @analysis[:confidence],
          severity: @analysis[:severity],
          agent_mode: @agent_mode
        }
      )
    rescue StandardError => e
      Rails.logger.warn("[SentriqAI] Could not create ticket note: #{e.message}")
    end

    def persist_investigation_record!
      inv = @detection.investigations.recent_first.first
      summary_text = @analysis[:incident_summary].to_s

      causes_json = (@analysis[:root_cause_hypotheses] || []).map do |h|
        {
          "hypothesis" => h[:hypothesis],
          "likelihood" => h[:likelihood],
          "rationale" => h[:rationale]
        }
      end

      if inv
        inv.update_columns(
          summary: summary_text,
          observed_evidence: @analysis[:evidence] || [],
          possible_causes: causes_json,
          evidence_gaps: @analysis[:missing_evidence] || [],
          recommended_steps: @analysis[:recommended_actions] || [],
          limitations: @analysis[:analysis_limitations],
          confidence_score: @analysis[:confidence],
          agent_mode: @agent_mode,
          requires_human_review: @analysis[:requires_human_approval],
          updated_at: Time.current
        )
      else
        @detection.investigations.create!(
          user: @current_user || User.first,
          status: "completed",
          summary: summary_text,
          observed_evidence: @analysis[:evidence] || [],
          possible_causes: causes_json,
          evidence_gaps: @analysis[:missing_evidence] || [],
          recommended_steps: @analysis[:recommended_actions] || [],
          limitations: @analysis[:analysis_limitations],
          confidence_score: @analysis[:confidence],
          agent_mode: @agent_mode,
          requires_human_review: @analysis[:requires_human_approval]
        )
      end
    rescue StandardError => e
      Rails.logger.warn("[SentriqAI] Investigation persistence warning: #{e.message}")
    end

    def record_audit_event!(trackable, action)
      AuditEvent.create!(
        trackable: trackable,
        user: @current_user,
        action: action,
        details: {
          classification: @analysis[:classification],
          severity: @analysis[:severity],
          confidence: @analysis[:confidence],
          requires_human_approval: @analysis[:requires_human_approval],
          agent_mode: @agent_mode,
          context_hash: @analysis[:context_hash]
        }
      )
    rescue StandardError => e
      Rails.logger.warn("[SentriqAI] AuditEvent logging warning: #{e.message}")
    end
  end
end
