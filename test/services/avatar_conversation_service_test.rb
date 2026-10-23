# frozen_string_literal: true

require "test_helper"

class AvatarConversationServiceTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "Avatar Analyst",
      email: "avatar.analyst@sentriq.local",
      role: "analyst"
    )

    @detection = Detection.create!(
      title: "Suspicious PowerShell Ingress",
      description: "powershell.exe -enc dGVzdA== executed on endpoint",
      hostname: "WKSTN-AVATAR-01",
      severity: "critical",
      status: "new",
      process_name: "powershell.exe",
      process_id: 3344,
      command_line: "powershell.exe -enc dGVzdA==",
      triggered_at: Time.current
    )
  end

  test "parses root cause question and returns structured hypothesis and speech text" do
    result = AvatarConversationService.new(
      query: "Saldırının olası kök nedeni nedir?",
      detection_id: @detection.id,
      current_user: @analyst
    ).call

    assert result[:success]
    assert_equal :root_cause, result[:intent]
    assert_includes result[:response], "Olası Kök Neden Analizi"
    assert_includes result[:speech_text], "kök neden"
    assert_equal "root_cause_explained", result[:action_taken]

    # Verify message persistence
    assert_equal 2, CopilotMessage.where(detection: @detection).count
  end

  test "parses create ticket natural language command and creates ticket" do
    assert_nil @detection.tickets.first

    result = AvatarConversationService.new(
      query: "Bu olay için ticket oluştur.",
      detection_id: @detection.id,
      current_user: @analyst
    ).call

    assert result[:success]
    assert_equal :create_ticket, result[:intent]
    assert_equal "ticket_created", result[:action_taken]
    assert_includes result[:speech_text], "Ticket oluşturuldu"

    ticket = @detection.reload.tickets.first
    assert_not_nil ticket
    assert_match(/^SQT-/, ticket.ticket_number)
    assert_equal "critical", ticket.priority

    # Audit event verified
    audit = AuditEvent.find_by(trackable: ticket, action: "copilot_avatar_interaction")
    assert_not_nil audit
  end

  test "parses prevention question and explains immediate and hardening steps" do
    result = AvatarConversationService.new(
      query: "Bu saldırı tekrar nasıl önlenebilir ve tedbirler nedir?",
      detection_id: @detection.id,
      current_user: @analyst
    ).call

    assert result[:success]
    assert_equal :prevention, result[:intent]
    assert_includes result[:response], "Önleyici Tedbirler"
    assert_includes result[:speech_text], "ağ izolasyonu"
  end

  test "parses escalation command and shifts ticket to pending_review" do
    ticket = Ticket.create!(
      title: "Escalation Target",
      description: "Needs escalation",
      priority: "high",
      status: "open",
      detection: @detection,
      user: @analyst
    )

    result = AvatarConversationService.new(
      query: "Bu olayı insan incelemesine gönder.",
      detection_id: @detection.id,
      ticket_id: ticket.id,
      current_user: @analyst
    ).call

    assert result[:success]
    assert_equal :escalate_to_human, result[:intent]
    assert_equal "ticket_escalated", result[:action_taken]
    assert_equal "pending_review", ticket.reload.status
  end

  test "parses summarize command and provides concise executive summary" do
    result = AvatarConversationService.new(
      query: "Bu olayda tam olarak ne oldu? Bulguları özetle.",
      detection_id: @detection.id,
      current_user: @analyst
    ).call

    assert result[:success]
    assert_equal :summarize, result[:intent]
    assert_includes result[:response], "Olay Özeti"
  end
end
