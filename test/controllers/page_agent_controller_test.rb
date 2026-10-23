# frozen_string_literal: true

require "test_helper"

class PageAgentControllerTest < ActionDispatch::IntegrationTest
  setup do
    @detection = Detection.create!(
      title: "Suspicious DLL Injection in lsass.exe",
      severity: "high",
      status: "new",
      hostname: "DC-AUTH-01",
      process_name: "mimikatz.exe",
      process_id: 1104,
      command_line: "mimikatz.exe sekurlsa::logonpasswords",
      triggered_at: 1.minute.ago,
      raw_telemetry: { cmdline: "sekurlsa::logonpasswords" }
    )

    @routine_detection = Detection.create!(
      title: "Dünkü tatbikat tamamlandı - Rutin kontrol",
      severity: "low",
      status: "open",
      hostname: "WS-DEV-12",
      process_name: "routine_check.exe",
      process_id: 2012,
      command_line: "routine_check.exe",
      triggered_at: 5.minutes.ago,
      raw_telemetry: { cmdline: "routine_check.exe" }
    )
  end

  test "POST /page_agent/execute runs in-page agent, enforces HITL for high threat, returns pending_review" do
    assert_difference("Ticket.count", 1) do
      post page_agent_execute_path,
           params: {
             instruction: "Bu yüksek öncelikli tespiti incele, otomatik ticket aç, RAG'e sor ve raporla",
             page_url: "/detections/#{@detection.id}",
             page_context: { detection_id: @detection.id, hostname: @detection.hostname },
             human_intervention: false
           },
           as: :json

      assert_response :ok
      json = JSON.parse(response.body)

      assert json["success"]
      assert json["verified"]
      assert_not_nil json["ticket"]
      assert_equal "pending_review", json["ticket"]["status"], "High threat must be placed in pending_review"
      assert_equal true, json["decision"]["requires_human_approval"]
      assert_equal "SIMULATED", json["decision"]["containment_status"]
      assert json["steps"].is_a?(Array)
      assert json["steps"].size >= 4
      assert_match(/Page-Agent Investigation Report/, json["report"])
    end
  end

  test "POST /page_agent/execute runs routine drill and resolves" do
    post page_agent_execute_path,
         params: {
           instruction: "Dünkü tatbikat tamamlandı, incele",
           page_url: "/detections/#{@routine_detection.id}",
           page_context: { detection_id: @routine_detection.id, hostname: @routine_detection.hostname },
           human_intervention: false
         },
         as: :json

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert_equal "resolved", json["ticket"]["status"]
    assert_equal false, json["decision"]["requires_human_approval"]
  end

  test "POST /page_agent/ragie_search returns RAG chunks" do
    post page_agent_ragie_search_path,
         params: { query: "ransomware vssadmin containment" },
         as: :json

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert json.key?("provider")
    assert json["results"].is_a?(Array)
  end

  test "POST /page_agent/set_api_key validates and saves key" do
    post page_agent_set_api_key_path,
         params: { api_key: "gsk_testdummyapikey12345", provider: "groq" },
         as: :json

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert_match(/Groq/, json["provider"])
  end

  test "POST /page_agent/set_api_key rejects empty key" do
    post page_agent_set_api_key_path,
         params: { api_key: "" },
         as: :json

    assert_response :unprocessable_entity
    json = JSON.parse(response.body)
    assert_equal false, json["success"]
  end
end
