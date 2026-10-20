class InvestigationNote < ApplicationRecord
  NOTE_TYPES = %w[analyst_comment correction escalation approval closed_as_fp].freeze

  belongs_to :investigation
  belongs_to :user

  validates :body, presence: true
  validates :note_type, presence: true, inclusion: { in: NOTE_TYPES }

  scope :chronological, -> { order(created_at: :asc) }
end
