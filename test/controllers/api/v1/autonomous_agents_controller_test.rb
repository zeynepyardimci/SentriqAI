# frozen_string_literal: true

require "test_helper"

class Api::V1::AutonomousAgentsControllerTest < ActionDispatch::IntegrationTest
  setup do
    @agent_user = User.create!(
      name: "Autonomous Sentinel Bot",
      email: "bot-#{SecureRandom.hex(4)}@sentriq.ai",
      role: "analyst",
      demo_token: "sentinel-agent-token-#{SecureRandom.hex(4)}"
    )

    @detection = Detection.create!(
      title: "LSASS Memory Dump Attempt via comsvcs.dll",
      severity: "high",
      status: "new",
      hostname: "DC-PRIMARY-01",
      process_name: "rundll32.exe",
      process_id: 3412,
      command_line: "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 640 dump.dmp full",
      triggered_at: 5.minutes.ago,
      raw_telemetry: { cmdline: "comsvcs.dll MiniDump", target: "lsass.exe" }
    )
  end

  test "POST /api/v1/agent/autonomous_ingest rejects unauthorized requests" do
    post api_v1_agent_autonomous_ingest_path,
         params: { detection_id: @detection.id },
         as: :json

    assert_response :unauthorized
    json = JSON.parse(response.body)
    assert_equal "unauthorized", json["error"]
  end

  test "POST /api/v1/agent/autonomous_ingest executes zero-touch triage with valid bearer token" do
    assert_difference("Ticket.count", 1) do
      post api_v1_agent_autonomous_ingest_path,
           headers: { "Authorization" => "Bearer #{@agent_user.demo_token}" },
           params: { detection_id: @detection.id },
           as: :json

      assert_response :ok
      json = JSON.parse(response.body)

      assert json["success"]
      assert_equal 1, json["processed_count"]
      assert_equal 1, json["results"].size

      res = json["results"].first
      assert_match(/^SQT-/, res["ticket_number"])
      assert_equal @detection.id, res["detection_id"]
      assert_includes %w[pending_review resolved open], res["status"]

      # Verify execution logs are returned to caller
      assert json["logs"].is_a?(Array)
      assert json["logs"].any? { |l| l.include?("ZERO human intervention") }
    end
  end
end
