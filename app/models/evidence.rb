class Evidence < ApplicationRecord
  EVIDENCE_TYPES = %w[
    process_spawn
    network_connection
    file_write
    registry_tamper
    powershell_script
    dns_query
    user_logon
  ].freeze

  belongs_to :detection

  validates :evidence_type, presence: true, inclusion: { in: EVIDENCE_TYPES }
  validates :occurred_at, presence: true
  validates :description, presence: true

  scope :chronological, -> { order(occurred_at: :asc) }
end
