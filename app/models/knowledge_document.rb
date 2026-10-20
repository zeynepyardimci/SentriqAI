class KnowledgeDocument < ApplicationRecord
  CATEGORIES = %w[runbook mitre_technique threat_intel policy incident_procedure].freeze

  has_many :knowledge_chunks, dependent: :destroy
  has_many :source_references, dependent: :destroy

  validates :title, presence: true
  validates :category, presence: true, inclusion: { in: CATEGORIES }
  validates :content, presence: true

  after_save :reindex_chunks, if: :saved_change_to_content?

  def reindex_chunks
    knowledge_chunks.destroy_all
    # Split content by double newlines (paragraphs) or ~500 chars
    paragraphs = content.split(/\n{2,}/).map(&:strip).reject(&:blank?)
    paragraphs.each_with_index do |para, idx|
      # Combine title and paragraph words for indexing
      raw_text = "#{title} #{category} #{external_reference} #{para}"
      cleaned_keywords = raw_text.downcase.gsub(/[^a-z0-9_\-\s]/, " ").split.uniq.reject { |w| w.length < 3 }.join(" ")
      knowledge_chunks.create!(
        chunk_index: idx,
        chunk_text: para,
        keywords: cleaned_keywords
      )
    end
  end
end
