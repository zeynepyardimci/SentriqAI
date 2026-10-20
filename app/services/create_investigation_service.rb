class CreateInvestigationService
  def initialize(detection:, user:, payload:, agent_mode: "simulated_local")
    @detection = detection.is_a?(Detection) ? detection : Detection.find(detection)
    @user = user
    @payload = payload
    @agent_mode = agent_mode
  end

  def call
    validated_data = InvestigationSchemaValidator.validate(@payload)

    ActiveRecord::Base.transaction do
      investigation = Investigation.create!(
        detection: @detection,
        user: @user,
        status: "completed",
        summary: validated_data["summary"],
        observed_evidence: validated_data["observed_evidence"] || [],
        possible_causes: validated_data["possible_causes"] || [],
        evidence_gaps: validated_data["evidence_gaps"] || [],
        recommended_steps: validated_data["recommended_steps"] || [],
        limitations: validated_data["limitations"] || "Automated analysis based on synthetic telemetry. Requires human verification before critical response actions.",
        requires_human_review: validated_data.fetch("requires_human_review", true),
        confidence_score: validated_data["confidence_score"] || 85,
        agent_mode: @agent_mode,
        raw_response: validated_data
      )

      # Persist source references if provided and valid
      references = validated_data["source_references"] || []
      references.each do |ref|
        doc_id = ref["document_id"] || ref[:document_id]
        doc = KnowledgeDocument.find_by(id: doc_id)
        next unless doc

        investigation.source_references.create!(
          knowledge_document: doc,
          quote: ref["quote"] || ref[:quote] || "Document reference #{doc.title}",
          relevance_explanation: ref["relevance_explanation"] || ref[:relevance_explanation] || "Correlated internal runbook/mitre document.",
          chunk_index: ref["chunk_index"] || ref[:chunk_index]
        )
      end

      # Transition detection status from new -> open -> investigating if needed
      if @detection.status == "new"
        @detection.transition_to!("open", user: @user, reason: "Auto-opened for AI investigation")
        @detection.transition_to!("investigating", user: @user, reason: "AI Investigation Agent analysis initiated")
      elsif @detection.status == "open"
        @detection.transition_to!("investigating", user: @user, reason: "AI Investigation Agent analysis initiated")
      end

      AuditEvent.create!(
        trackable: investigation,
        user: @user,
        action: "investigation_completed",
        details: {
          agent_mode: @agent_mode,
          confidence_score: investigation.confidence_score,
          references_count: investigation.source_references.count
        }
      )

      investigation
    end
  end
end
