# frozen_string_literal: true

class CopilotMessage < ApplicationRecord
  belongs_to :detection, optional: true
  belongs_to :ticket, optional: true
  belongs_to :user, optional: true

  validates :role, presence: true, inclusion: { in: %w[user avatar system] }
  validates :content, presence: true

  scope :chronological, -> { order(created_at: :asc) }
  scope :recent_first, -> { order(created_at: :desc) }

  def user_message?
    role == "user"
  end

  def avatar_message?
    role == "avatar"
  end
end
