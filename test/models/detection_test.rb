require "test_helper"

class DetectionTest < ActiveSupport::TestCase
  setup do
    @detection = Detection.create!(
      title: "Test PowerShell Obfuscation",
      severity: "high",
      status: "new",
      hostname: "test-host-01",
      triggered_at: 10.minutes.ago
    )
  end

  test "valid status transition flow succeeds" do
    assert_equal "new", @detection.status

    @detection.transition_to!("open")
    assert_equal "open", @detection.status

    @detection.transition_to!("investigating")
    assert_equal "investigating", @detection.status

    @detection.transition_to!("pending_review")
    assert_equal "pending_review", @detection.status

    @detection.transition_to!("solved")
    assert_equal "solved", @detection.status
  end

  test "invalid transition from new to solved is rejected" do
    assert_raises(ActiveRecord::RecordInvalid) do
      @detection.transition_to!("solved")
    end
    assert_equal "new", @detection.reload.status
  end

  test "invalid transition from open to pending_review is rejected" do
    @detection.transition_to!("open")
    assert_raises(ActiveRecord::RecordInvalid) do
      @detection.transition_to!("pending_review")
    end
  end

  test "controlled reopening from solved status is supported" do
    @detection.transition_to!("open")
    @detection.transition_to!("investigating")
    @detection.transition_to!("pending_review")
    @detection.transition_to!("solved")

    @detection.transition_to!("reopened")
    assert_equal "reopened", @detection.status

    @detection.transition_to!("investigating")
    assert_equal "investigating", @detection.status
  end

  test "SLA checker flags detection triggered 16 minutes ago as at_risk" do
    @detection.update_columns(triggered_at: 16.minutes.ago, sla_risk: false)

    assert_not @detection.sla_risk?
    @detection.check_sla!(Time.current)

    assert @detection.reload.sla_risk?
    assert_not_nil @detection.sla_breached_at
  end

  test "SLA checker does not flag detection triggered 5 minutes ago" do
    @detection.update_columns(triggered_at: 5.minutes.ago, sla_risk: false)

    @detection.check_sla!(Time.current)
    assert_not @detection.reload.sla_risk?
  end

  test "SLA checker ignores low severity detections" do
    @detection.update_columns(severity: "low", triggered_at: 30.minutes.ago, sla_risk: false)

    @detection.check_sla!(Time.current)
    assert_not @detection.reload.sla_risk?
  end
end
