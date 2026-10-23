# frozen_string_literal: true

class PageAgentController < ApplicationController
  protect_from_forgery except: [:execute, :ragie_search, :set_api_key]

  # POST /page_agent/execute
  def execute
    instruction = params[:instruction].presence || "Bu tespiti incele, otomatik ticket aç, Ragie RAG'e sor ve raporla"
    page_url = params[:page_url].presence || request.referer || root_path
    page_context = params[:page_context] || {}
    human_intervention = ActiveModel::Type::Boolean.new.cast(params[:human_intervention]) || false
    confirmed_action = params[:confirmed_action].presence

    service = PageAgentService.new(
      instruction: instruction,
      page_url: page_url,
      page_context: page_context,
      current_user: current_user,
      human_intervention: human_intervention,
      confirmed_action: confirmed_action
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
