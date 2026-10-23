class Detection < ApplicationRecord
  SEVERITIES = %w[low medium high critical].freeze
  STATUSES = %w[new open investigating pending_review solved reopened].freeze

  VALID_TRANSITIONS = {
    "new" => %w[open],
    "open" => %w[investigating],
    "investigating" => %w[pending_review],
    "pending_review" => %w[solved investigating],
    "solved" => %w[reopened],
    "reopened" => %w[investigating open]
  }.freeze

  SLA_THRESHOLD_MINUTES = 15

  belongs_to :assigned_to, class_name: "User", optional: true
  has_many :evidences, dependent: :destroy
  has_many :investigations, dependent: :destroy
  has_many :tickets, dependent: :nullify
  has_many :copilot_messages, dependent: :nullify
  has_many :audit_events, as: :trackable, dependent: :destroy

  validates :title, presence: true
  validates :severity, presence: true, inclusion: { in: SEVERITIES }
  validates :status, presence: true, inclusion: { in: STATUSES }
  validates :hostname, presence: true
  validates :triggered_at, presence: true

  validate :validate_status_transition, on: :update, if: :will_save_change_to_status?

  scope :active, -> { where.not(status: "solved") }
  scope :at_risk, -> { where(sla_risk: true) }
  scope :by_severity, -> { order(Arel.sql("CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END")) }
  scope :recent_first, -> { order(triggered_at: :desc) }

  def self.can_transition?(from_status, to_status)
    return false if from_status.to_s == to_status.to_s
    allowed = VALID_TRANSITIONS[from_status.to_s] || []
    allowed.include?(to_status.to_s)
  end

  def can_transition_to?(next_status)
    self.class.can_transition?(status, next_status)
  end

  def transition_to!(next_status, user: nil, reason: nil)
    next_status = next_status.to_s
    old_status = status

    unless can_transition_to?(next_status)
      errors.add(:status, "cannot transition from '#{old_status}' to '#{next_status}'. Allowed: #{(VALID_TRANSITIONS[old_status] || []).join(', ')}")
      raise ActiveRecord::RecordInvalid, self
    end

    self.status = next_status
    save!

    AuditEvent.create!(
      trackable: self,
      user: user,
      action: "status_changed",
      details: {
        from: old_status,
        to: next_status,
        reason: reason
      }
    )
  end

  def self.sla_threshold_minutes
    ENV.fetch("SLA_THRESHOLD_MINUTES", "15").to_i
  end

  def check_sla!(current_time = Time.current)
    return if status.in?(%w[solved pending_review investigating])
    return unless severity.in?(%w[high critical])

    threshold = self.class.sla_threshold_minutes
    elapsed_minutes = (current_time - triggered_at) / 60.0
    if elapsed_minutes >= threshold && !sla_risk?
      update_columns(sla_risk: true, sla_breached_at: current_time)
      AuditEvent.create!(
        trackable: self,
        user: nil,
        action: "sla_breached",
        details: {
          threshold_minutes: threshold,
          elapsed_minutes: elapsed_minutes.round(1),
          severity: severity
        }
      )
    end
  end

  private

  def validate_status_transition
    old_status = status_was
    unless self.class.can_transition?(old_status, status)
      errors.add(:status, "cannot transition from '#{old_status}' to '#{status}'. Allowed: #{(VALID_TRANSITIONS[old_status] || []).join(', ')}")
    end
  end
end
