# frozen_string_literal: true

require "test_helper"

class TicketStateMachineTransitionTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "Triage Analyst",
      email: "triage-analyst-#{SecureRandom.hex(4)}@sentriq.local",
      role: "analyst"
    )

    @lead = User.create!(
      name: "Lead Reviewer",
      email: "lead-reviewer-#{SecureRandom.hex(4)}@sentriq.local",
      role: "lead_analyst"
    )

    @detection = Detection.create!(
      title: "Suspicious DLL Injection",
      severity: "high",
      status: "open",
      hostname: "WKSTN-TEST-99",
      process_name: "rundll32.exe",
      triggered_at: 5.minutes.ago
    )

    @ticket = Ticket.create!(
      title: "High Risk DLL Injection Alert",
      description: "rundll32.exe executed suspicious unverified binary payload",
      priority: "high",
      status: "open",
      detection: @detection,
      user: @analyst
    )
  end

  # Test 1: open → pending_review geçişi doğru çalışır.
  test "1. transition from open to pending_review succeeds with audit trail" do
    assert_equal "open", @ticket.status
    assert @ticket.can_transition_to?("pending_review")

    @ticket.escalate_to_human!(
      reason: "High risk DLL injection requires Level 2 analyst review",
      user: @analyst
    )

    assert_equal "pending_review", @ticket.reload.status
    assert_equal 1, @ticket.ticket_notes.where(note_type: "escalation").count

    audit = AuditEvent.find_by(trackable: @ticket, action: "ticket_status_changed")
    assert_not_nil audit
    assert_equal "open", audit.details["from"]
    assert_equal "pending_review", audit.details["to"]
  end

  # Test 2: resolved ticket insan incelemesine gönderildiğinde kontrollü iş kuralı uygulanır.
  test "2. resolved ticket escalated to human review applies controlled reopen workflow to pending_review" do
    # Move ticket to resolved
    @ticket.transition_to!("investigating")
    @ticket.transition_to!("pending_review")
    @ticket.apply_human_decision!(
      decision: "approved",
      notes: "Initial resolution",
      reviewer: @lead
    )
    assert_equal "resolved", @ticket.reload.status

    # Direct illegal transition directly from resolved to pending_review is blocked
    refute @ticket.can_transition_to?("pending_review")
    assert_raises(ActiveRecord::RecordInvalid) do
      @ticket.transition_to!("pending_review")
    end

    # BUT business method escalate_to_human! executes controlled reopen workflow
    assert_nothing_raised do
      @ticket.escalate_to_human!(
        reason: "Yeniden analiz: Yeni IoC bulgusu tespit edildi, insan incelemesi gerekiyor",
        user: @analyst
      )
    end

    assert_equal "pending_review", @ticket.reload.status

    # Audit events verify both reopen (resolved->open) and escalate (open->pending_review)
    audits = AuditEvent.where(trackable: @ticket, action: "ticket_status_changed").order(created_at: :asc)
    reopen_audit = audits.detect { |a| a.details["from"] == "resolved" && a.details["to"] == "open" }
    escalate_audit = audits.detect { |a| a.details["from"] == "open" && a.details["to"] == "pending_review" }

    assert_not_nil reopen_audit, "Must record audit event for reopening resolved ticket"
    assert_not_nil escalate_audit, "Must record audit event for escalating reopened ticket"
  end

  # Test 3: closed ticket geçerli reopen süreci olmadan değiştirilmez.
  test "3. closed ticket cannot be escalated directly to pending_review without reopening" do
    @ticket.transition_to!("closed")
    assert_equal "closed", @ticket.reload.status

    # Direct escalation must fail with clear descriptive message
    err = assert_raises(ActiveRecord::RecordInvalid) do
      @ticket.escalate_to_human!(reason: "Kapalı bilete eskalasyon denemesi", user: @analyst)
    end
    assert_includes err.message, "closed"

    # Only explicit reopen! transitions it back to open first
    @ticket.reopen!(user: @lead, reason: "Yetkili analist tarafından yeniden açıldı")
    assert_equal "open", @ticket.reload.status

    # Now it can safely transition to pending_review
    @ticket.escalate_to_human!(reason: "Yeniden inceleme", user: @analyst)
    assert_equal "pending_review", @ticket.reload.status
  end

  # Test 4: İnsan onayı bekleyen ticket sebepsiz yere resolved olmaz.
  test "4. ticket in pending_review is never prematurely auto-resolved by analysis" do
    @ticket.transition_to!("pending_review")
    assert_equal "pending_review", @ticket.reload.status

    # Running contextual analyzer on ticket in pending_review
    result = TicketContextualAnalyzerService.new(ticket: @ticket, current_user: @analyst).call
    assert result[:success]

    # Must stay in pending_review!
    assert_equal "pending_review", @ticket.reload.status
    assert_not_equal "resolved", @ticket.status
  end

  # Test 5: İzin verilmeyen geçişler anlaşılır hata döndürür.
  test "5. disallowed state transitions raise RecordInvalid with explicit allowed list" do
    # From open: cannot go directly to unknown or invalid status
    assert_raises(ActiveRecord::RecordInvalid) do
      @ticket.transition_to!("nonexistent_status")
    end

    @ticket.transition_to!("closed")
    assert_equal "closed", @ticket.reload.status

    # From closed: only open is allowed
    err = assert_raises(ActiveRecord::RecordInvalid) do
      @ticket.transition_to!("pending_review")
    end
    assert_includes err.message, "cannot transition from 'closed' to 'pending_review'"
    assert_includes err.message, "Allowed: open"
  end

  # Test 6: Avatar komutu doğru ticket üzerinde çalışır.
  test "6. avatar escalate_to_human command successfully escalates open or resolved ticket" do
    # A. Open ticket escalation
    avatar_service_open = AvatarConversationService.new(
      query: "Bu olayı insan incelemesine gönder",
      ticket_id: @ticket.id,
      current_user: @analyst
    )
    result_open = avatar_service_open.call
    assert_equal :escalate_to_human, result_open[:intent]
    assert_equal "ticket_escalated", result_open[:action_taken]
    assert_equal "pending_review", @ticket.reload.status

    # B. Transition to resolved
    @ticket.apply_human_decision!(decision: "approved", notes: "Approved by lead", reviewer: @lead)
    assert_equal "resolved", @ticket.reload.status

    # C. Avatar escalation on resolved ticket must NOT throw RecordInvalid!
    avatar_service_resolved = AvatarConversationService.new(
      query: "Bu olayı insan incelemesine gönder",
      ticket_id: @ticket.id,
      current_user: @analyst
    )
    result_resolved = avatar_service_resolved.call

    assert_equal :escalate_to_human, result_resolved[:intent]
    assert_equal "ticket_reopened_and_escalated", result_resolved[:action_taken]
    assert_equal "pending_review", @ticket.reload.status
    assert_includes result_resolved[:speech_text], "pending review"
  end

  # Test 7: Backend, UI ve audit log aynı son durumu gösterir.
  test "7. backend DB status, returned payload status, and audit log all show consistent status" do
    avatar_service = AvatarConversationService.new(
      query: "Bu olayı insan incelemesine gönder",
      ticket_id: @ticket.id,
      current_user: @analyst
    )
    result = avatar_service.call

    # Backend DB status
    @ticket.reload
    assert_equal "pending_review", @ticket.status

    # UI/Payload status
    assert_equal "pending_review", result[:ticket_status]

    # Audit log
    latest_audit = AuditEvent.where(trackable: @ticket, action: "ticket_status_changed").order(created_at: :desc).first
    assert_not_nil latest_audit
    assert_equal "pending_review", latest_audit.details["to"]
  end

  # Test 8: Geçerli geçiş sonrasında doğru denetim kaydı oluşturulur.
  test "8. valid transition creates comprehensive audit event with user, reason, from and to states" do
    reason_text = "Seviye 2 analist triyajı için eskalasyon sağlandı."
    @ticket.escalate_to_human!(reason: reason_text, user: @analyst)

    audit = AuditEvent.where(trackable: @ticket, action: "ticket_status_changed").last
    assert_not_nil audit
    assert_equal @analyst.id, audit.user_id
    assert_equal "open", audit.details["from"]
    assert_equal "pending_review", audit.details["to"]
    assert_equal reason_text, audit.details["reason"]
  end
end
