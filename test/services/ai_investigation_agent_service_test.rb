require "test_helper"

class AiInvestigationAgentServiceTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(
      name: "Agent Test User",
      email: "agent.tester@sentriq.local",
      role: "analyst"
    )

    @doc = KnowledgeDocument.create!(
      title: "RB-0105: Obfuscated PowerShell Execution Runbook",
      category: "runbook",
      content: "Adversaries use powershell encodedcommand to hide payload scripts from static scanners."
    )

    @detection = Detection.create!(
      title: "Suspicious PowerShell Spawning",
      severity: "high",
      status: "new",
      hostname: "FIN-PC-01",
      process_name: "powershell.exe",
      process_id: 4120,
      parent_process_name: "winword.exe",
      command_line: "powershell.exe -NoP -Enc VGVzdA==",
      triggered_at: 5.minutes.ago
    )

    @detection.evidences.create!(
      evidence_type: "process_spawn",
      occurred_at: 5.minutes.ago,
      description: "winword spawned powershell with encoded command."
    )
  end

  test "AI Investigation Agent generates structured report and persists references" do
    investigation = AiInvestigationAgentService.new(detection: @detection, user: @user).call

    assert_not_nil investigation
    assert_equal "completed", investigation.status
    assert_includes %w[live_llm simulated_local], investigation.agent_mode

    # Verify structured fields
    assert_not_empty investigation.observed_evidence
    assert_not_empty investigation.possible_causes
    assert_not_empty investigation.evidence_gaps
    assert_not_empty investigation.recommended_steps
    assert investigation.requires_human_review?

    # Verify source reference matches
    assert_not_empty investigation.source_references
    ref = investigation.source_references.first
    assert_equal @doc.id, ref.knowledge_document_id
    assert_not_empty ref.quote

    # Verify detection was moved to investigating
    assert_equal "investigating", @detection.reload.status

    # Verify AuditEvent was logged
    audit = AuditEvent.find_by(trackable: investigation, action: "investigation_completed")
    assert_not_nil audit
    assert_equal @user.id, audit.user_id
  end

  test "AI Investigation Agent handles detections without matching runbooks cleanly" do
    unmatched_det = Detection.create!(
      title: "Rare Custom Utility Execution",
      severity: "low",
      status: "open",
      hostname: "DEV-01",
      process_name: "custom_inhouse_tool.exe",
      command_line: "custom_inhouse_tool.exe --run",
      triggered_at: 10.minutes.ago
    )

    investigation = AiInvestigationAgentService.new(detection: unmatched_det, user: @user).call

    assert_not_nil investigation
    # Should not fabricate bogus source references
    assert_equal 0, investigation.source_references.count
    assert_equal "investigating", unmatched_det.reload.status
  end
end
