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
  end

  test "POST /page_agent/execute runs in-page agent with zero human intervention" do
    assert_difference("Ticket.count", 1) do
      post page_agent_execute_path,
           params: {
             instruction: "Bu tespiti incele, otomatik ticket aç, RAG'e sor ve raporla",
             page_url: "/detections/#{@detection.id}",
             page_context: { detection_id: @detection.id, hostname: @detection.hostname },
             human_intervention: false
           },
           as: :json

      assert_response :ok
      json = JSON.parse(response.body)

      assert json["success"]
      assert_not_nil json["ticket"]
      assert_equal "resolved", json["ticket"]["status"]
      assert json["steps"].is_a?(Array)
      assert json["steps"].size >= 3
      assert_match(/Page-Agent Investigation Report/, json["report"])
    end
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
end
