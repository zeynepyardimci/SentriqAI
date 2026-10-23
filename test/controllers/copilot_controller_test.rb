# frozen_string_literal: true

require "test_helper"

class CopilotControllerTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(
      name: "Copilot Controller User",
      email: "copilot.controller@sentriq.local",
      role: "lead_analyst"
    )

    @detection = Detection.create!(
      title: "Active Ingress Beaconing",
      hostname: "WKSTN-COPILOT-01",
      severity: "critical",
      status: "new",
      process_name: "powershell.exe",
      triggered_at: Time.current
    )
  end

  test "GET /copilot renders index page successfully with detection context" do
    get copilot_url(detection_id: @detection.id)
    assert_response :ok
    assert_select "title", /Sentriq AI/
    assert_includes response.body, "Canlı AI Güvenlik Analisti"
    assert_includes response.body, "Derinlemesine Olay Araştırması"
    assert_includes response.body, "Otonom SOC Ajanı"
  end

  test "POST /copilot/chat returns structured avatar response with speech text and intent" do
    post copilot_chat_url, params: {
      query: "Bu olayda tam olarak ne oldu?",
      detection_id: @detection.id
    }.to_json, headers: { "Content-Type" => "application/json" }

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert_not_nil json["response"]
    assert_not_nil json["speech_text"]
    assert_equal "summarize", json["intent"]
  end

  test "POST /copilot/autonomous_triage runs zero-touch agent pipeline and creates ticket" do
    assert_nil @detection.tickets.first

    post copilot_autonomous_triage_url, params: {
      detection_id: @detection.id
    }.to_json, headers: { "Content-Type" => "application/json" }

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert json["logs"].is_a?(Array)
    assert json["logs"].any?
    assert_not_nil json["ticket"]
    assert_includes json["speech_text"], "Bilet oluşturuldu"

    ticket = @detection.reload.tickets.first
    assert_not_nil ticket
  end

  test "POST /copilot/load_scenario loads requested synthetic demo scenario" do
    post copilot_load_scenario_url, params: {
      scenario: "scenario_a"
    }.to_json, headers: { "Content-Type" => "application/json" }

    assert_response :ok
    json = JSON.parse(response.body)
    assert json["success"]
    assert_equal "low", json["severity"]
    assert_includes json["title"], "Tatbikat"
  end
end
