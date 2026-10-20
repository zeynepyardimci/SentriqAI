require "test_helper"

class RequestHumanReviewTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(
      name: "Triage Lead",
      email: "triage.lead@sentriq.local",
      role: "lead_analyst"
    )

    @detection = Detection.create!(
      title: "Ransomware Inhibit Recovery Triage",
      severity: "high",
      status: "open",
      hostname: "FILESRV-01",
      triggered_at: 10.minutes.ago
    )

    @detection.transition_to!("investigating")

    @investigation = @detection.investigations.create!(
      user: @user,
      summary: "Preliminary analysis of vssadmin deletion",
      status: "completed",
      agent_mode: "simulated_local"
    )
  end

  test "escalate_to_lead transitions detection to pending_review and creates audit trail" do
    RequestHumanReviewService.new(
      detection: @detection,
      user: @user,
      action: "escalate_to_lead",
      note_body: "Requires confirmation from SOC Lead before firewall block."
    ).call

    assert_equal "pending_review", @detection.reload.status
    assert_equal 1, @investigation.investigation_notes.count
    note = @investigation.investigation_notes.first
    assert_equal "escalation", note.note_type

    audit = AuditEvent.find_by(trackable: @detection, action: "human_review_escalate_to_lead")
    assert_not_nil audit
  end

  test "approve_and_solve transitions from pending_review to solved" do
    @detection.transition_to!("pending_review")

    RequestHumanReviewService.new(
      detection: @detection,
      user: @user,
      action: "approve_and_solve",
      note_body: "False positive verified: approved backup maintenance script."
    ).call

    assert_equal "solved", @detection.reload.status
    audit = AuditEvent.find_by(trackable: @detection, action: "human_review_approve_and_solve")
    assert_not_nil audit
  end

  test "request_changes transitions from pending_review back to investigating" do
    @detection.transition_to!("pending_review")

    RequestHumanReviewService.new(
      detection: @detection,
      user: @user,
      action: "request_changes",
      note_body: "Please collect memory dump before resolving."
    ).call

    assert_equal "investigating", @detection.reload.status
  end
end
