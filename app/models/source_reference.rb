class SourceReference < ApplicationRecord
  belongs_to :investigation
  belongs_to :knowledge_document

  validates :quote, presence: true
  validates :relevance_explanation, presence: true
end
