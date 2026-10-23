# frozen_string_literal: true

require "test_helper"

class CopilotMessageTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(
      name: "Copilot Test User",
      email: "copilot.user@sentriq.local",
      role: "analyst"
    )

    @detection = Detection.create!(
      title: "Test Beaconing Detection",
      hostname: "WKSTN-TEST-99",
      severity: "high",
      status: "new",
      triggered_at: Time.current
    )
  end

  test "validates role inclusion and content presence" do
    msg = CopilotMessage.new(detection: @detection, role: "invalid_role", content: "")
    assert_not msg.valid?
    assert_includes msg.errors[:role], "is not included in the list"
    assert_includes msg.errors[:content], "can't be blank"

    msg.role = "user"
    msg.content = "Bu olayda tam olarak ne oldu?"
    assert msg.valid?
  end

  test "persists user, avatar, and system messages with chronological ordering" do
    m1 = CopilotMessage.create!(detection: @detection, user: @user, role: "user", content: "Kök neden nedir?")
    m2 = CopilotMessage.create!(detection: @detection, role: "avatar", content: "Olası kök neden PowerShell LOLBin yürütmesidir.")
    m3 = CopilotMessage.create!(detection: @detection, role: "system", content: "Ticket açıldı.")

    ordered = CopilotMessage.where(detection: @detection).chronological
    assert_equal [m1.id, m2.id, m3.id], ordered.pluck(:id)
    assert m1.user_message?
    assert m2.avatar_message?
  end
end
