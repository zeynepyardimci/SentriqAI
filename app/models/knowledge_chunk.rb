class KnowledgeChunk < ApplicationRecord
  belongs_to :knowledge_document

  validates :chunk_index, presence: true
  validates :chunk_text, presence: true

  # RAG search: ranked search across chunk_text and keywords
  def self.search(query, limit: 5)
    return none if query.blank?

    tokens = query.to_s.downcase.gsub(/[^a-z0-9_\-\s]/, " ").split.reject { |t| t.length < 3 }
    return none if tokens.empty?

    # Build SQL ILIKE condition for tokens
    conditions = tokens.map { "chunk_text ILIKE ? OR keywords ILIKE ?" }
    params = tokens.flat_map { |t| ["%#{t}%", "%#{t}%"] }

    where(conditions.join(" OR "), *params)
      .limit(limit)
  end
end
