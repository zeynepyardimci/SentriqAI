# frozen_string_literal: true

class PageAgentController < ApplicationController
  rescue_from ActionDispatch::Http::Parameters::ParseError, with: :handle_parse_error
  rescue_from ActionController::BadRequest, with: :handle_bad_request

  public

  def handle_bad_request(exception)
    Rails.logger.error "PageAgentController BadRequest: #{exception.message}"
    render json: { success: false, error: 'Bad request: #{exception.message}' }, status: :bad_request
  end
  def handle_parse_error(exception)
    Rails.logger.error "PageAgentController ParseError: #{exception.message}"
    render json: { success: false, error: "Parse error: #{exception.message}" }, status: :bad_request
  end

  protect_from_forgery except: [:execute, :ragie_search, :set_api_key]

  # POST /page_agent/execute
  def execute
    instruction = params[:instruction].presence || "Bu tespiti incele, otomatik ticket aç, Ragie RAG'e sor ve raporla"
    page_url     = params[:page_url].presence || request.referer || root_path

    # Safely permit all nested page_context keys to avoid UnfilteredParameters error
    raw_ctx = params[:page_context]
    page_context = if raw_ctx.respond_to?(:permit!)
                     raw_ctx.permit!.to_h
                   elsif raw_ctx.is_a?(Hash)
                     raw_ctx
                   else
                     {}
                   end

    if session[:last_handled_detection_id].present? && page_context[:last_handled_detection_id].blank?
      page_context[:last_handled_detection_id] = session[:last_handled_detection_id]
    end

    human_intervention = ActiveModel::Type::Boolean.new.cast(params[:human_intervention]) || false
    confirmed_action   = params[:confirmed_action].presence

    service = PageAgentService.new(
      instruction: instruction,
      page_url: page_url,
      page_context: page_context,
      current_user: current_user,
      human_intervention: human_intervention,
      confirmed_action: confirmed_action
    )

    begin
      result = service.call
      render json: result, status: (result[:success] ? :ok : :unprocessable_entity)
    rescue StandardError => e
      Rails.logger.error "PageAgentController#execute failed: #{e.message}"
      render json: { success: false, error: e.message }, status: :internal_server_error
    end
  end

  # POST /page_agent/ragie_search
  def ragie_search
    query = params.require(:query)
    limit = params[:limit] || 4

    result = RagieRetrievalService.new(query, limit: limit).call

    render json: result, status: :ok
  end

  # POST /page_agent/set_api_key
  def set_api_key
    key = params[:api_key].to_s.strip
    provider = params[:provider].to_s.presence || "auto"

    if key.blank?
      render json: { success: false, error: "API anahtarı boş olamaz" }, status: :unprocessable_entity
      return
    end

    if key.start_with?("gsk_") || provider == "groq"
      ENV["GROQ_API_KEY"] = key
      provider_name = "Groq Live (Llama 3.3 70B)"
      persist_key("groq_api_key", key)
    elsif key.start_with?("xai-") || provider == "grok"
      ENV["GROK_API_KEY"] = key
      provider_name = "Grok (xAI Live)"
      persist_key("grok_api_key", key)
    else
      ENV["GROQ_API_KEY"] = key
      provider_name = "Groq / OpenAI Uyumlu Canlı Motor"
      persist_key("groq_api_key", key)
    end

    render json: {
      success: true,
      message: "#{provider_name} başarıyla etkinleştirildi ve kalıcı olarak kaydedildi!",
      provider: provider_name
    }, status: :ok
  end

  private

  def persist_key(field, value)
    keys_file = Rails.root.join("config", "sentriq_api_keys.json")
    existing = begin
      File.exist?(keys_file) ? JSON.parse(File.read(keys_file)) : {}
    rescue StandardError
      {}
    end
    existing[field] = value
    File.write(keys_file, JSON.pretty_generate(existing))
  rescue StandardError => e
    Rails.logger.warn("Could not write sentriq_api_keys.json: #{e.message}")
  end
end
