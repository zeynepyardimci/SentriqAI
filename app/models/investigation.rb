class Investigation < ApplicationRecord
  STATUSES = %w[in_progress completed failed].freeze
  AGENT_MODES = %w[live_llm simulated_local].freeze

  belongs_to :detection
  belongs_to :user
  has_many :source_references, dependent: :destroy
  has_many :investigation_notes, dependent: :destroy
  has_many :audit_events, as: :trackable, dependent: :destroy

  validates :status, presence: true, inclusion: { in: STATUSES }
  validates :summary, presence: true
  validates :agent_mode, presence: true, inclusion: { in: AGENT_MODES }
  validates :confidence_score, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }

  scope :recent_first, -> { order(created_at: :desc) }

  def live_llm?
    agent_mode == "live_llm"
  end

  def simulated_local?
    agent_mode == "simulated_local"
  end
end
