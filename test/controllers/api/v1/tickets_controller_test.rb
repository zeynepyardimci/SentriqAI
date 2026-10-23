require "test_helper"

class Api::V1::TicketsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @agent_user = User.create!(
      name: "Autonomous SOAR Agent",
      email: "soar.agent@sentriq.local",
      role: "analyst",
      demo_token: "test-valid-agent-token-12345"
    )

    @detection = Detection.create!(
      title: "Active Process Beaconing",
      severity: "high",
      status: "new",
      hostname: "WKSTN-TEST-01",
      triggered_at: 10.minutes.ago
    )

    @headers = {
      "Authorization" => "Bearer #{@agent_user.demo_token}",
      "Content-Type" => "application/json"
    }
  end

  # Requirement 1: Agent API üzerinden ticket açar ve ticket veritabanında kalıcıdır.
  test "1. agent opens ticket via API and ticket is persisted in database" do
    assert_difference "Ticket.count", 1 do
      post api_v1_tickets_url, params: {
        title: "Malicious DLL Injection Detected",
        description: "Process explorer.exe loaded unsigned module from temp directory",
        priority: "high",
        detection_id: @detection.id,
        assigned_agent: "SOAR-Agent-X"
      }.to_json, headers: @headers
    end

    assert_response :created
    json = JSON.parse(response.body)

    assert_not_nil json["id"]
    assert_match(/^SQT-\d{4}-\d{6}$/, json["ticket_number"])
    assert_equal "open", json["status"]
    assert_equal "high", json["priority"]

    # Verify persistence
    persisted = Ticket.find(json["id"])
    assert_equal "Malicious DLL Injection Detected", persisted.title
    assert_equal @detection.id, persisted.detection_id
  end

  # Requirement 2: API üzerinden ticket ayrıntıları okunabilir.
  test "2. agent can read ticket details via API" do
    ticket = Ticket.create!(
      title: "API Read Test Ticket",
      description: "Detailed description of telemetry event",
      priority: "medium",
      status: "open",
      user: @agent_user
    )

    get api_v1_ticket_url(ticket), headers: @headers

    assert_response :ok
    json = JSON.parse(response.body)
    assert_equal ticket.id, json["id"]
    assert_equal "API Read Test Ticket", json["title"]
    assert_equal "open", json["status"]
  end

  # Requirement 3: Yetkisiz agent ticket açamaz veya yetkisiz verileri okuyamaz.
  test "3. unauthorized agent without valid token cannot open or read tickets" do
    invalid_headers = {
      "Authorization" => "Bearer invalid-or-fake-token-999",
      "Content-Type" => "application/json"
    }

    # Cannot create
    post api_v1_tickets_url, params: { title: "Hacked", description: "Attemp" }.to_json, headers: invalid_headers
    assert_response :unauthorized
    assert_equal "unauthorized", JSON.parse(response.body)["error"]

    # Cannot read
    ticket = Ticket.create!(title: "Secret", description: "Desc", user: @agent_user)
    get api_v1_ticket_url(ticket), headers: invalid_headers
    assert_response :unauthorized
  end

  # Requirement 4: Tekrarlanan aynı istek için idempotency davranışı doğrulanır.
  test "4. duplicate requests with same Idempotency-Key return existing ticket without re-creating" do
    idempotency_key = "idemp-test-unique-key-7788"
    params_payload = {
      title: "Idempotent Alert Submission",
      description: "Should only be created once",
      priority: "high"
    }.to_json

    headers_with_idempotency = @headers.merge("Idempotency-Key" => idempotency_key)

    # First request creates
    assert_difference "Ticket.count", 1 do
      post api_v1_tickets_url, params: params_payload, headers: headers_with_idempotency
      assert_response :created
    end
    first_ticket_id = JSON.parse(response.body)["id"]

    # Second request with SAME idempotency key returns 200 OK and same ticket ID
    assert_no_difference "Ticket.count" do
      post api_v1_tickets_url, params: params_payload, headers: headers_with_idempotency
      assert_response :ok
      assert_equal "true", response.headers["X-Idempotent-Replay"]
      assert_equal first_ticket_id, JSON.parse(response.body)["id"]
    end
  end

  # Requirement 10: İnsan kararı audit log'a kaydedilir ve agent tarafından API üzerinden okunabilir.
  test "10. human decision is saved to audit log and readable by agent via API" do
    lead_reviewer = User.create!(
      name: "Chief SOC Analyst",
      email: "chief.soc@sentriq.local",
      role: "lead_analyst"
    )

    ticket = Ticket.create!(
      title: "Privilege Escalation Review",
      description: "Needs human signoff",
      priority: "critical",
      status: "pending_review",
      user: @agent_user
    )

    # Human analyst reviews and resolves the ticket in the system
    ticket.apply_human_decision!(
      decision: "approved",
      notes: "Containment authorized and host quarantined.",
      reviewer: lead_reviewer
    )

    # External agent queries /api/v1/tickets/:id/human_decision via API
    get human_decision_api_v1_ticket_url(ticket), headers: @headers

    assert_response :ok
    json = JSON.parse(response.body)

    assert_equal "resolved", json["status"]
    assert_equal "approved", json["human_decision"]
    assert_equal "Containment authorized and host quarantined.", json["human_decision_notes"]
    assert_equal lead_reviewer.id, json["human_reviewer"]["id"]

    # Verify audit event persistence
    audit = AuditEvent.find_by(trackable: ticket, action: "ticket_human_reviewed")
    assert_not_nil audit
    assert_equal lead_reviewer.id, audit.user_id
  end

  # Requirement: Agent creates ticket with auto_triage: true and receives structured LLM decision schema
  test "agent creates ticket with auto_triage and receives structured decision schema" do
    assert_difference "Ticket.count", 1 do
      post api_v1_tickets_url, params: {
        title: "Volume Shadow Copy Deletion Detected via vssadmin",
        description: "Process vssadmin.exe executed 'delete shadows /all /quiet' on SRV-FILE-01",
        priority: "critical",
        detection_id: @detection.id,
        auto_triage: true
      }.to_json, headers: @headers
    end

    assert_response :created
    json = JSON.parse(response.body)

    assert_not_nil json["id"]
    assert_not_nil json["triage"]

    triage = json["triage"]
    assert_equal "critical", triage["severity"]
    assert_not_nil triage["confidence"]
    assert_not_nil triage["confidence_note"]
    assert_not_nil triage["classification"]
    assert triage["evidence"].is_a?(Array)
    assert triage["evidence"].any?
    assert_not_nil triage["reasoning"]
    assert_not_nil triage["matched_runbook"]
    assert_not_nil triage["recommended_action"]
    assert_equal true, triage["requires_human_approval"]

    # Critical threat must be held in pending_review for human signoff, never automatically executed
    persisted = Ticket.find(json["id"])
    assert_equal "pending_review", persisted.status
  end

  # Requirement: Low-risk / routine event is not closed irrevocably, remains open for review
  test "low-risk routine event is not closed automatically and remains open" do
    post api_v1_tickets_url, params: {
      title: "Routine Scheduled Backup Script Execution",
      description: "Weekly maintenance script completed. Reference drill quote 'acil yedekleme tatbikatı'.",
      priority: "low",
      auto_triage: true
    }.to_json, headers: @headers

    assert_response :created
    json = JSON.parse(response.body)
    triage = json["triage"]

    assert_equal "low", triage["severity"]
    assert_equal false, triage["requires_human_approval"]

    # Not closed irrevocably!
    persisted = Ticket.find(json["id"])
    assert_equal "open", persisted.status
  end

  # Requirement: POST /api/v1/tickets/:id/human_decision applies human decision via API
  test "human decision applied via POST api_v1_ticket_human_decision creates simulated action and resolves" do
    ticket = Ticket.create!(
      title: "Ransomware Ingress Review",
      description: "Requires containment approval",
      priority: "critical",
      status: "pending_review",
      user: @agent_user
    )

    post human_decision_api_v1_ticket_url(ticket), params: {
      decision: "approved",
      notes: "Containment approved by SOC Lead."
    }.to_json, headers: @headers

    assert_response :ok
    json = JSON.parse(response.body)

    assert_equal "resolved", json["status"]
    assert_equal "approved", json["human_decision"]
    assert_equal "simulated_host_isolation", json["simulated_action_taken"]

    # Verify simulation audit event
    sim_audit = AuditEvent.find_by(trackable: ticket, action: "simulated_host_isolation_executed")
    assert_not_nil sim_audit
    assert_equal true, sim_audit.details["simulated"]
  end

  # Requirement: Missing required parameters returns 400 Bad Request
  test "missing required title or description returns 400 Bad Request" do
    post api_v1_tickets_url, params: { priority: "high" }.to_json, headers: @headers
    assert_response :bad_request
    json = JSON.parse(response.body)
    assert_equal "bad_request", json["error"]
  end
end
