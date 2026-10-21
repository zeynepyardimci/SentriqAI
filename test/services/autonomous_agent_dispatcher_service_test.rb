# frozen_string_literal: true

require "test_helper"

class AutonomousAgentDispatcherServiceTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(
      name: "Autonomous Lead",
      email: "lead-auto-#{SecureRandom.hex(4)}@sentriq.ai",
      role: "lead_analyst",
      demo_token: "auto-lead-token-#{SecureRandom.hex(4)}"
    )

    @detection = Detection.create!(
      title: "Shadow Copy Deletion Detected via vssadmin",
      severity: "critical",
      status: "new",
      hostname: "WIN-SERVER-SEC01",
      process_name: "vssadmin.exe",
      process_id: 8812,
      command_line: "vssadmin.exe delete shadows /all /quiet",
      triggered_at: 10.minutes.ago,
      raw_telemetry: { cmdline: "vssadmin.exe delete shadows /all /quiet", parent: "winword.exe" }
    )
  end

  test "autonomously creates ticket and triages detection with zero human intervention" do
    service = AutonomousAgentDispatcherService.new(detection: @detection, current_user: @user)

    assert_difference("Ticket.count", 1) do
      outcome = service.call
      assert outcome[:success]
      assert_equal 1, outcome[:processed_count]

      result = outcome[:results].first
      ticket = result[:ticket]

      assert_equal "critical", ticket.priority
      assert_match(/Sentriq-Autonomous-Agent/, ticket.assigned_agent)
      assert_equal @detection.id, ticket.detection_id

      # Because it's a critical ransomware detection, it must autonomously transition to pending_review for human confirmation
      assert_equal "pending_review", ticket.status
      assert_equal "pending_review", result[:outcome]

      # Verify agent research note was autonomously attached
      agent_note = ticket.ticket_notes.where(author_type: "agent").last
      assert_not_nil agent_note
      assert_match(/Autonomous Investigation Trace/, agent_note.body)

      # Verify execution logs show zero human intervention
      assert outcome[:logs].any? { |l| l.include?("ZERO human intervention") }
    end
  end

  test "enforces idempotency on repeated autonomous ingestion runs" do
    service = AutonomousAgentDispatcherService.new(detection: @detection, current_user: @user)
    first_run = service.call
    assert_equal 1, first_run[:processed_count]

    assert_no_difference("Ticket.count") do
      second_run = service.call
      assert second_run[:success]
      assert_equal "reused_existing", second_run[:results].first[:action]
    end
  end
end
