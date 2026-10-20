require "test_helper"

class DetectionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(
      name: "Controller Test User",
      email: "controller.test@sentriq.local",
      role: "lead_analyst"
    )

    @detection = Detection.create!(
      title: "Suspicious PowerShell Execution Test",
      severity: "high",
      status: "new",
      hostname: "CONTROLLER-PC-01",
      process_name: "powershell.exe",
      command_line: "powershell.exe -Enc Q29udHJvbGxlclRlc3Q=",
      triggered_at: 20.minutes.ago
    )

    @detection.evidences.create!(
      evidence_type: "process_spawn",
      occurred_at: 20.minutes.ago,
      description: "powershell spawned test event"
    )

    @doc = KnowledgeDocument.create!(
      title: "RB-Controller: Obfuscated PowerShell Runbook",
      category: "runbook",
      content: "Powershell encodedcommand flag indicates base64 obfuscation."
    )
  end

  test "should get index" do
    get detections_url
    assert_response :success
    assert_select ".brand-title", "SENTRIQ AI"
    assert_select ".data-table"
  end

  test "should filter detections by severity" do
    get detections_url, params: { severity: "high" }
    assert_response :success
    assert_includes response.body, @detection.title
  end

  test "should show detection details" do
    get detection_url(@detection)
    assert_response :success
    assert_includes response.body, @detection.hostname
    assert_includes response.body, "Execution Lineage & Process Tree"
  end

  test "should trigger AI investigation" do
    post investigate_detection_url(@detection)
    assert_redirected_to detection_url(@detection)

    follow_redirect!
    assert_response :success
    assert_equal "investigating", @detection.reload.status
    assert_not_empty @detection.investigations
    assert_includes response.body, "AI Investigation Report"
  end

  test "should process human review escalation" do
    @detection.transition_to!("open")
    @detection.transition_to!("investigating")

    post review_detection_url(@detection), params: {
      review_action: "escalate_to_lead",
      note_body: "Requires senior review before firewall action."
    }

    assert_redirected_to detection_url(@detection)
    assert_equal "pending_review", @detection.reload.status
  end

  test "should evaluate SLAs via check_sla action" do
    post check_sla_detections_url
    assert_redirected_to detections_url
    follow_redirect!
    assert_response :success
    assert_includes flash[:notice], "SLA Check executed"
  end
end
