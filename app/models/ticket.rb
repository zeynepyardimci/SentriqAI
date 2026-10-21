class Ticket < ApplicationRecord
  STATUSES = %w[open investigating pending_review resolved closed].freeze
  PRIORITIES = %w[low medium high critical].freeze

  VALID_TRANSITIONS = {
    "open" => %w[investigating pending_review resolved closed],
    "investigating" => %w[pending_review resolved closed],
    "pending_review" => %w[resolved investigating closed],
    "resolved" => %w[open closed],
    "closed" => %w[open]
  }.freeze

  belongs_to :detection, optional: true
  belongs_to :user, optional: true
  belongs_to :human_reviewer, class_name: "User", optional: true
  has_many :ticket_notes, dependent: :destroy
  has_many :audit_events, as: :trackable, dependent: :destroy

  validates :ticket_number, presence: true, uniqueness: true
  validates :title, presence: true
  validates :description, presence: true
  validates :status, presence: true, inclusion: { in: STATUSES }
  validates :priority, presence: true, inclusion: { in: PRIORITIES }
  validates :idempotency_key, uniqueness: true, allow_nil: true

  validate :validate_status_transition, on: :update, if: :will_save_change_to_status?

  before_validation :generate_ticket_number, on: :create

  scope :recent_first, -> { order(created_at: :desc) }
  scope :pending_review, -> { where(status: "pending_review") }
  scope :active, -> { where.not(status: %w[resolved closed]) }

  def can_transition_to?(next_status)
    return false if status == next_status.to_s
    allowed = VALID_TRANSITIONS[status] || []
    allowed.include?(next_status.to_s)
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
      action: "ticket_status_changed",
      details: {
        from: old_status,
        to: next_status,
        reason: reason
      }
    )
  end

  def escalate_to_human!(reason:, user: nil)
    ActiveRecord::Base.transaction do
      if status != "pending_review"
        transition_to!("pending_review", user: user, reason: reason)
      end

      ticket_notes.create!(
        user: user,
        author_type: user ? "human" : "system",
        author_name: user ? user.name : (assigned_agent || "Automated Agent"),
        note_type: "escalation",
        body: reason,
        metadata: { trigger: "ai_uncertainty_or_high_risk" }
      )
    end
  end

  def apply_human_decision!(decision:, notes:, reviewer:)
    ActiveRecord::Base.transaction do
      self.human_decision = decision.to_s
      self.human_decision_notes = notes.to_s
      self.human_reviewer = reviewer
      self.human_reviewed_at = Time.current

      target_status = case decision.to_s
                      when "approved", "resolved", "dismissed" then "resolved"
                      when "request_changes", "deeper_investigation" then "investigating"
                      when "closed" then "closed"
                      else "resolved"
                      end

      if can_transition_to?(target_status)
        self.status = target_status
      end

      save!

      ticket_notes.create!(
        user: reviewer,
        author_type: "human",
        author_name: reviewer.name,
        note_type: "human_decision",
        body: notes.presence || "Human review decision: #{decision}",
        metadata: { decision: decision, reviewer_role: reviewer.role }
      )

      AuditEvent.create!(
        trackable: self,
        user: reviewer,
        action: "ticket_human_reviewed",
        details: {
          decision: decision,
          notes: notes,
          final_status: status
        }
      )
    end
  end

  private

  def generate_ticket_number
    return if ticket_number.present?

    year = Time.current.year
    loop do
      random_seq = SecureRandom.random_number(900_000) + 100_000 # 6 digits
      candidate = "SQT-#{year}-#{random_seq}"
      unless self.class.exists?(ticket_number: candidate)
        self.ticket_number = candidate
        break
      end
    end
  end

  def validate_status_transition
    old_status = status_was
    allowed = VALID_TRANSITIONS[old_status] || []
    unless allowed.include?(status)
      errors.add(:status, "cannot transition from '#{old_status}' to '#{status}'. Allowed: #{allowed.join(', ')}")
    end
  end
end
