class User < ApplicationRecord
  ROLES = %w[analyst senior_analyst lead_analyst admin].freeze

  has_many :investigations, dependent: :destroy
  has_many :investigation_notes, dependent: :destroy
  has_many :audit_events, dependent: :nullify
  has_many :assigned_detections, class_name: "Detection", foreign_key: "assigned_to_id", dependent: :nullify

  validates :email, presence: true, uniqueness: { case_sensitive: false }, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :name, presence: true
  validates :role, presence: true, inclusion: { in: ROLES }
  validates :demo_token, presence: true, uniqueness: true

  before_validation :generate_demo_token, on: :create

  def lead_or_admin?
    role.in?(%w[lead_analyst admin senior_analyst])
  end

  private

  def generate_demo_token
    self.demo_token ||= SecureRandom.hex(16)
  end
end
