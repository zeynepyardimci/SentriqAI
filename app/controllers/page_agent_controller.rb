# frozen_string_literal: true

class PageAgentController < ApplicationController
  protect_from_forgery except: [:execute, :ragie_search]

  # POST /page_agent/execute
  def execute
    instruction = params[:instruction].presence || "Bu tespiti incele, otomatik ticket aç, Ragie RAG'e sor ve raporla"
    page_url = params[:page_url].presence || request.referer || root_path
    page_context = params[:page_context] || {}
    human_intervention = ActiveModel::Type::Boolean.new.cast(params[:human_intervention]) || false

    service = PageAgentService.new(
      instruction: instruction,
      page_url: page_url,
      page_context: page_context,
      current_user: current_user,
      human_intervention: human_intervention
    )

    result = service.call

    if result[:success]
      render json: result, status: :ok
    else
      render json: result, status: :unprocessable_entity
    end
  end

  # POST /page_agent/ragie_search
  def ragie_search
    query = params.require(:query)
    limit = params[:limit] || 4

    result = RagieRetrievalService.new(query, limit: limit).call

    render json: result, status: :ok
  end
end
