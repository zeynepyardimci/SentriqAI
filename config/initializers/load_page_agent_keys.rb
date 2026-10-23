# frozen_string_literal: true

# Load persisted API keys on boot
keys_file = Rails.root.join("config", "sentriq_api_keys.json")
if File.exist?(keys_file)
  begin
    keys = JSON.parse(File.read(keys_file))
    ENV["GROQ_API_KEY"] ||= keys["groq_api_key"] if keys["groq_api_key"].present?
    ENV["GROK_API_KEY"] ||= keys["grok_api_key"] if keys["grok_api_key"].present?
    ENV["OPENAI_API_KEY"] ||= keys["openai_api_key"] if keys["openai_api_key"].present?
  rescue StandardError => e
    Rails.logger.warn("Failed to load sentriq_api_keys.json: #{e.message}")
  end
end
