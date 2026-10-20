class KnowledgeDocumentsController < ApplicationController
  def index
    @documents = KnowledgeDocument.includes(:knowledge_chunks).order(:title)
  end

  def show
    @document = KnowledgeDocument.includes(:knowledge_chunks).find(params[:id])
  end
end
