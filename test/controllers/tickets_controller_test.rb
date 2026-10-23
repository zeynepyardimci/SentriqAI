# frozen_string_literal: true

require "test_helper"

class TicketsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(
      name: "Security Lead Analyst",
      email: "lead-analyst-#{SecureRandom.hex(4)}@sentriq.ai",
      role: "lead_analyst",
      demo_token: "lead-tok-#{SecureRandom.hex(4)}"
    )

    # Establish authenticated session
    post session_path, params: { user_id: @user.id }

    @detection1 = Detection.create!(
      title: "Active Lateral Movement via PsExec",
      severity: "critical",
      status: "new",
      hostname: "DC-PRIMARY-01",
      process_name: "psexec.exe",
      process_id: 3412,
      command_line: "psexec.exe \\\\target cmd.exe",
      triggered_at: 2.minutes.ago,
      raw_telemetry: { cmdline: "psexec.exe" }
    )

    @detection2 = Detection.create!(
      title: "Ransomware Volume Shadow Deletion",
      severity: "high",
      status: "new",
      hostname: "FILE-SRV-02",
      process_name: "vssadmin.exe",
      process_id: 5120,
      command_line: "vssadmin.exe delete shadows /all /quiet",
      triggered_at: 1.minute.ago,
      raw_telemetry: { cmdline: "vssadmin.exe delete shadows" }
    )
  end

  test "POST /tickets/autonomous_ingest succeeds without CookieOverflow and does NOT write large logs to session" do
    assert_difference("Ticket.count", 2) do
      post autonomous_ingest_tickets_path,
           headers: { "HTTP_REFERER" => tickets_path }

      assert_response :redirect
      assert_redirected_to tickets_path
      assert_not_nil flash[:notice]

      # Critical Assertion: session[:last_autonomous_logs] MUST BE NIL in the cookie store
      assert_nil session[:last_autonomous_logs], "Large autonomous logs must NEVER be stored in session cookie"

      # Verify cookie payload size remains small and well below 4096 bytes (4KB limit)
      session_cookie = cookies["_sentriq_ai_session"]
      if session_cookie.present?
        assert session_cookie.bytesize < 600, "Session cookie size (#{session_cookie.bytesize} bytes) must remain small"
      end

      # Verify audit events were created in database
      assert AuditEvent.where(action: "autonomous_agent_zero_touch_triage").exists?
    end
  end

  test "POST /tickets/autonomous_ingest responds with JSON API format when requested as json" do
    assert_difference("Ticket.count", 2) do
      post autonomous_ingest_tickets_path(format: :json),
           as: :json

      assert_response :ok
      json = JSON.parse(response.body)

      assert json["success"]
      assert_equal 2, json["processed_count"]
      assert json["tickets"].is_a?(Array)
      assert_equal 2, json["tickets"].size

      first_ticket = json["tickets"].first
      assert first_ticket.key?("ticket_id")
      assert first_ticket.key?("ticket_number")
      assert first_ticket.key?("status")

      # No cookie overflow
      assert_nil session[:last_autonomous_logs]
    end
  end

  test "POST /tickets/autonomous_ingest failure returns clean error without cookie explosion" do
    orig = AutonomousAgentDispatcherService.instance_method(:call)
    begin
      AutonomousAgentDispatcherService.define_method(:call) do
        { success: false, error: "Simulated SIEM telemetry timeout" }
      end

      post autonomous_ingest_tickets_path(format: :json), as: :json

      assert_response :unprocessable_entity
      json = JSON.parse(response.body)

      assert_equal false, json["success"]
      assert_equal "Simulated SIEM telemetry timeout", json["error"]
      assert_nil session[:last_autonomous_logs]
    ensure
      AutonomousAgentDispatcherService.define_method(:call, orig)
    end
  end

  test "GET /tickets index displays execution stream from AuditEvent" do
    ticket = Ticket.create!(
      title: "Test Stream Alert",
      description: "Sample",
      priority: "high",
      status: "pending_review",
      user: @user
    )

    AuditEvent.create!(
      trackable: ticket,
      user: @user,
      action: "autonomous_agent_zero_touch_triage",
      details: { outcome: "pending_review", intent: "active_threat_containment" }
    )

    get tickets_path

    assert_response :ok
    assert_includes response.body, "Son Otonom Ajan Yürütme Kayıtları"
    assert_includes response.body, ticket.ticket_number
    assert_includes response.body, "active_threat_containment"
  end
end
