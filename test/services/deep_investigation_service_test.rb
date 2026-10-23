# frozen_string_literal: true

require "test_helper"

class DeepInvestigationServiceTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "Investigation Analyst",
      email: "investigation.analyst@sentriq.local",
      role: "analyst"
    )

    @detection = Detection.create!(
      title: "Volume Shadow Copy Deletion via vssadmin",
      description: "vssadmin.exe delete shadows /all /quiet executed",
      hostname: "WKSTN-FIN-01",
      severity: "critical",
      status: "new",
      process_name: "vssadmin.exe",
      process_id: 4096,
      parent_process_name: "cmd.exe",
      command_line: "vssadmin.exe delete shadows /all /quiet",
      triggered_at: Time.current
    )

    @detection.evidences.create!(
      evidence_type: "process_spawn",
      description: "vssadmin.exe spawned under cmd.exe with elevated privileges",
      occurred_at: 1.minute.ago
    )

    @ticket = Ticket.create!(
      title: "Ticket for Deep Investigation",
      description: "Deep investigation ticket",
      priority: "critical",
      status: "open",
      detection: @detection,
      user: @analyst
    )
  end

  test "executes all 10 steps of deep investigation and generates dual reports" do
    result = DeepInvestigationService.new(detection: @detection, ticket: @ticket, current_user: @analyst).call

    assert result[:success]
    steps = result[:steps]

    # Verify 10 steps
    assert_not_nil steps[:step_1_telemetry]
    assert_equal "vssadmin.exe", steps[:step_1_telemetry][:process_name]

    assert_not_nil steps[:step_2_timeline]
    assert steps[:step_2_timeline].is_a?(Array)
    assert steps[:step_2_timeline].size >= 2

    assert_not_nil steps[:step_3_process_tree]
    assert_includes steps[:step_3_process_tree][:target_node], "vssadmin.exe"

    assert_not_nil steps[:step_4_scenarios]
    assert steps[:step_4_scenarios].any? { |s| s[:technique].include?("T1490") }

    assert_not_nil steps[:step_5_root_cause]
    assert_includes steps[:step_5_root_cause][:primary][:hypothesis], "Fidye Yazılımı"
    assert_equal "Critical", steps[:step_5_root_cause][:primary][:likelihood]

    assert_not_nil steps[:step_6_evidence_and_gaps]
    assert steps[:step_6_evidence_and_gaps][:proven_findings].any?
    assert steps[:step_6_evidence_and_gaps][:unknown_gaps].any?

    assert_not_nil steps[:step_7_runbooks]
    assert_not_nil steps[:step_8_prevention]
    assert steps[:step_8_prevention][:immediate_containment].any?

    assert_not_nil steps[:step_9_risk_and_hitl]
    assert_equal true, steps[:step_9_risk_and_hitl][:requires_human_approval]

    assert_equal "investigation_completed_and_verified", steps[:step_10_status]

    # Verify Dual Reports
    assert_includes result[:executive_summary], "YÖNETİCİ ÖZETİ"
    assert_includes result[:executive_summary], "OLASI KÖK NEDEN"

    assert_includes result[:technical_report], "TEKNİK İNCELEME"
    assert_includes result[:technical_report], "SÜREÇ SOYAĞACI"

    # Verify persistence in ticket llm_analysis
    assert_not_nil @ticket.reload.llm_analysis["deep_investigation"]
    assert_not_nil @ticket.llm_analysis["executive_summary"]
  end

  test "drill or backup scenario correctly identifies benign routine maintenance" do
    drill_detection = Detection.create!(
      title: "Dünkü Rutin Yedekleme Tatbikatı",
      description: "Zamanlanmış yedekleme tatbikatı başarıyla tamamlandı",
      hostname: "SRV-DRILL-01",
      severity: "low",
      status: "open",
      triggered_at: Time.current
    )

    result = DeepInvestigationService.new(detection: drill_detection, current_user: @analyst).call
    root_cause = result[:steps][:step_5_root_cause][:primary]

    assert_includes root_cause[:hypothesis], "Tatbikat"
    assert_equal false, result[:steps][:step_9_risk_and_hitl][:requires_human_approval]
  end
end
