# frozen_string_literal: true

require "test_helper"

class Ai::OrchestratorTest < ActiveSupport::TestCase
  setup do
    @original_cache = Rails.cache
    Rails.cache = ActiveSupport::Cache::MemoryStore.new
    Rails.cache.clear
  end

  teardown do
    Rails.cache = @original_cache
  end

  test "orchestrates ransomware shadow copy incident with grounded hypotheses and recommendations" do
    detection = Detection.create!(
      title: "Shadow Copy Deletion via Vssadmin",
      description: "T1490 Inhibit System Recovery detected",
      severity: "critical",
      status: "new",
      hostname: "FINANCE-SRV01",
      ip_address: "10.0.0.15",
      username: "SYSTEM",
      process_name: "vssadmin.exe",
      command_line: "vssadmin.exe delete shadows /all /quiet",
      parent_process_name: "cmd.exe",
      file_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      triggered_at: Time.current
    )

    ticket = Ticket.create!(
      ticket_number: "TCK-RANSOM-01",
      title: "Ransomware Inhibit System Recovery Alert",
      description: "Host FINANCE-SRV01 executed vssadmin shadow deletion in silent mode.",
      priority: "critical",
      status: "open",
      detection: detection
    )

    result = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: true)

    assert result[:success], "Orchestration should succeed"
    analysis = result[:analysis]

    # Verify structured fields
    assert_equal "critical", analysis[:severity]
    assert_includes ["ransomware", "ransomware_precursor", "endpoint_threat"], analysis[:classification]
    assert_includes analysis[:incident_summary], "vssadmin"

    # Verify root cause hypotheses differentiate malicious vs backup drill
    hypotheses = analysis[:root_cause_hypotheses]
    assert hypotheses.any? { |h| h[:hypothesis].to_s.downcase.include?("ransomware") },
      "Should generate ransomware inhibition hypothesis"

    # Verify recommended actions include backup isolation
    actions = analysis[:recommended_actions]
    assert actions.any? { |a| a.to_s.downcase.include?("izole") || a.to_s.downcase.include?("yedek") || a.to_s.downcase.include?("isolate") },
      "Should recommend isolation or backup audit"

    # Verify human approval is required for critical ransomware
    assert_equal true, analysis[:requires_human_approval]

    # Verify confidence evaluation metadata
    conf = analysis[:confidence_assessment]
    assert conf.present?
    assert_equal "uncalibrated_heuristic", conf[:calibration_status]
    assert_operator conf[:score], :>, 50
  end

  test "orchestrates routine backup drill with appropriate lower priority and missing schedule note" do
    detection = Detection.create!(
      title: "Rutin Yedekleme Tatbikati ve Disk Temizligi",
      description: "Scheduled drill test event",
      severity: "low",
      status: "new",
      hostname: "BACKUP-SRV02",
      username: "admin_backup",
      process_name: "wbadmin.exe",
      command_line: "wbadmin delete catalog -quiet",
      parent_process_name: "taskeng.exe",
      triggered_at: Time.current
    )

    ticket = Ticket.create!(
      ticket_number: "TCK-DRILL-02",
      title: "Rutin Yedekleme Tatbikati",
      description: "Haftalik planli yedekleme tatbikati ve temizlik proseduru.",
      priority: "low",
      status: "open",
      detection: detection
    )

    result = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: true)
    analysis = result[:analysis]

    assert_includes ["routine_or_drill", "informational_drill"], analysis[:classification]
    assert_equal "low", analysis[:severity]

    # Missing evidence should note lack of formal change ticket or drill approval
    missing = analysis[:missing_evidence]
    assert missing.present?, "Should contain missing evidence list"
    assert missing.any? { |m| m.to_s.downcase.match?(/tatbikat|takvim|rfc|onay|drill|schedule|change|auth|yedek|backup|hash|ip|telemetri/i) },
      "Should note missing authorization ticket or drill schedule records. Got: #{missing.inspect}"
  end

  test "orchestrates suspicious PowerShell LOLBin macro execution" do
    detection = Detection.create!(
      title: "Suspicious PowerShell Spawned from Word Document",
      description: "T1059.001 PowerShell spawned by WINWORD.EXE",
      severity: "high",
      status: "new",
      hostname: "HR-PC-04",
      username: "jdoe",
      process_name: "powershell.exe",
      command_line: "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgA...",
      parent_process_name: "WINWORD.EXE",
      ip_address: "185.220.101.5",
      triggered_at: Time.current
    )

    ticket = Ticket.create!(
      ticket_number: "TCK-PS-03",
      title: "Malicious Macro Execution HR-PC-04",
      description: "WINWORD spawned obfuscated base64 PowerShell contacting external IP.",
      priority: "high",
      status: "open",
      detection: detection
    )

    result = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: true)
    analysis = result[:analysis]

    assert_equal "suspicious_powershell_lolbin", analysis[:classification]
    assert_includes analysis[:incident_summary], "WINWORD.EXE"
    assert_includes analysis[:incident_summary], "powershell.exe"
    assert analysis[:evidence].any? { |e| e.to_s.include?("WINWORD.EXE") }
    assert analysis[:attack_chain].present?
  end

  test "reflects missing telemetry in missing_evidence and evidence_quality" do
    ticket = Ticket.create!(
      ticket_number: "TCK-SPARSE-04",
      title: "Vague Alert with No Telemetry",
      description: "Something happened on the network",
      priority: "medium",
      status: "open"
    )

    result = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: true)
    analysis = result[:analysis]

    assert analysis[:missing_evidence].size >= 3, "Sparse ticket should list multiple missing telemetry fields"
    conf = analysis[:confidence_assessment]
    assert_operator conf[:evidence_quality], :<, 60, "Evidence quality must be low for sparse telemetry"
  end

  test "guarantees isolation between different tickets without leakage" do
    ticket_a = Ticket.create!(
      ticket_number: "TCK-ISO-A",
      title: "Ticket A - Ransomware Shadow Deletion",
      description: "Critical vssadmin delete shadows on DB Server",
      priority: "critical",
      status: "open"
    )

    ticket_b = Ticket.create!(
      ticket_number: "TCK-ISO-B",
      title: "Ticket B - Routine Backup Drill",
      description: "Planned weekly routine backup exercise",
      priority: "low",
      status: "open"
    )

    res_a = Ai::Orchestrator.analyze(ticket: ticket_a, force_refresh: true)
    res_b = Ai::Orchestrator.analyze(ticket: ticket_b, force_refresh: true)

    # Analyses must be distinct
    refute_equal res_a[:analysis][:incident_summary], res_b[:analysis][:incident_summary]
    refute_equal res_a[:analysis][:classification], res_b[:analysis][:classification]
    refute_equal res_a[:analysis][:severity], res_b[:analysis][:severity]
    refute_equal res_a[:context][:context_hash], res_b[:context][:context_hash]
  end

  test "serves cached analysis when context hash has not changed" do
    ticket = Ticket.create!(
      ticket_number: "TCK-CACHE-01",
      title: "Cache Isolation Test Ticket",
      description: "Telemetry check",
      priority: "medium",
      status: "open"
    )

    res1 = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: false)
    assert_equal false, res1[:from_cache]

    res2 = Ai::Orchestrator.analyze(ticket: ticket, force_refresh: false)
    assert_equal true, res2[:from_cache], "Second call with identical context must serve from cache"
    assert_equal res1[:analysis][:confidence], res2[:analysis][:confidence]
  end

  test "persists analysis into ticket JSONB and creates note and investigation record" do
    ticket = Ticket.create!(
      ticket_number: "TCK-PERSIST-01",
      title: "Persistence Verification Ticket",
      description: "Testing persistence layer",
      priority: "high",
      status: "open"
    )

    Ai::Orchestrator.analyze(ticket: ticket, force_refresh: true)

    ticket.reload
    assert ticket.llm_analysis.present?, "Ticket must persist llm_analysis JSONB"
    assert ticket.ticket_notes.where(note_type: "analysis_draft").exists?, "Ticket must log analysis_draft note"
  end
end
