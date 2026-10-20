class TicketNote < ApplicationRecord
  AUTHOR_TYPES = %w[agent human system].freeze
  NOTE_TYPES = %w[finding escalation human_decision comment analysis_draft].freeze

  belongs_to :ticket
  belongs_to :user, optional: true

  validates :body, presence: true
  validates :author_type, presence: true, inclusion: { in: AUTHOR_TYPES }
  validates :note_type, presence: true, inclusion: { in: NOTE_TYPES }
  validates :author_name, presence: true

  scope :chronological, -> { order(created_at: :asc) }
end
