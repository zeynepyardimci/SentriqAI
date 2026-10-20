class AuditEvent < ApplicationRecord
  belongs_to :trackable, polymorphic: true
  belongs_to :user, optional: true

  validates :action, presence: true
  validates :created_at, presence: true

  scope :recent_first, -> { order(created_at: :desc) }

  before_validation :set_created_at, on: :create

  private

  def set_created_at
    self.created_at ||= Time.current
  end
end
