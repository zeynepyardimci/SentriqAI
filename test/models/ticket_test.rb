require "test_helper"

class TicketTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "Ticket Test Analyst",
      email: "ticket.analyst@sentriq.local",
      role: "analyst"
    )

    @lead = User.create!(
      name: "Ticket Test Lead",
      email: "ticket.lead@sentriq.local",
      role: "lead_analyst"
    )

    @ticket = Ticket.create!(
      title: "Suspicious DLL Injection",
      description: "DLL loaded into explorer.exe memory space",
      priority: "high",
      status: "open",
      user: @analyst
    )
  end

  test "generates unique ticket_number automatically" do
    assert_match(/^SQT-\d{4}-\d{6}$/, @ticket.ticket_number)
  end

  test "valid status transition flow succeeds" do
    assert_equal "open", @ticket.status

    @ticket.transition_to!("investigating")
    assert_equal "investigating", @ticket.status

    @ticket.transition_to!("pending_review")
    assert_equal "pending_review", @ticket.status

    @ticket.transition_to!("resolved")
    assert_equal "resolved", @ticket.status
  end

  test "escalate_to_human moves ticket to pending_review and creates escalation note" do
    @ticket.escalate_to_human!(reason: "Unusual privileged memory tampering detected", user: @analyst)

    assert_equal "pending_review", @ticket.reload.status
    assert_equal 1, @ticket.ticket_notes.count
    note = @ticket.ticket_notes.first
    assert_equal "escalation", note.note_type
    assert_includes note.body, "Unusual privileged memory tampering"
  end

  test "invalid status transition raises error" do
    @ticket.transition_to!("investigating")
    @ticket.transition_to!("pending_review")
    @ticket.transition_to!("resolved")

    # Invalid: cannot transition directly from resolved to pending_review
    assert_raises(ActiveRecord::RecordInvalid) do
      @ticket.transition_to!("pending_review")
    end
  end

  test "SLA check does not breach before threshold" do
    # 10 minutes elapsed (threshold is 15 minutes)
    travel_to 10.minutes.from_now do
      @ticket.check_sla!
      assert_equal "open", @ticket.reload.status
      assert_nil AuditEvent.find_by(trackable: @ticket, action: "ticket_sla_breached")
    end
  end

  test "SLA check breaches after threshold using travel_to and escalates to pending_review" do
    # 20 minutes elapsed (threshold is 15 minutes)
    travel_to 20.minutes.from_now do
      @ticket.check_sla!
      assert_equal "pending_review", @ticket.reload.status

      audit = AuditEvent.find_by(trackable: @ticket, action: "ticket_sla_breached")
      assert_not_nil audit
      assert_equal 15, audit.details["threshold_minutes"]
      assert_equal "high", audit.details["priority"]
    end
  end

  test "apply_human_decision records resolution, notes, reviewer, simulated action, and audit trail" do
    @ticket.transition_to!("pending_review")

    @ticket.apply_human_decision!(
      decision: "approved",
      notes: "False positive verified: legitimate IT maintenance script.",
      reviewer: @lead
    )

    assert_equal "resolved", @ticket.reload.status
    assert_equal "approved", @ticket.human_decision
    assert_equal @lead.id, @ticket.human_reviewer_id
    assert_not_nil @ticket.human_reviewed_at

    # Verify human review audit event
    audit = AuditEvent.find_by(trackable: @ticket, action: "ticket_human_reviewed")
    assert_not_nil audit
    assert_equal @lead.id, audit.user_id

    # Verify simulated host containment audit event
    sim_audit = AuditEvent.find_by(trackable: @ticket, action: "simulated_host_isolation_executed")
    assert_not_nil sim_audit
    assert_equal true, sim_audit.details["simulated"]
  end
end
