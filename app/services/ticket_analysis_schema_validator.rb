class TicketAnalysisSchemaValidator
  class ValidationError < StandardError; end

  REQUIRED_KEYS = %w[
    severity
    confidence
    classification
    evidence
    reasoning
    matched_runbook
    recommended_action
    requires_human_approval
  ].freeze

  def self.validate(payload)
    new(payload).validate!
  end

  def initialize(payload)
    @payload = payload
    @errors = []
  end

  def validate!
    raw = parse_payload(@payload)
    data = raw.respond_to?(:deep_stringify_keys) ? raw.deep_stringify_keys : raw

    # Normalize aliases for backward/forward compatibility
    data["severity"] ||= data["priority"]
    data["priority"] ||= data["severity"]
    data["classification"] ||= data["intent"]
    data["intent"] ||= data["classification"]
    data["reasoning"] ||= data["rationale"]
    data["rationale"] ||= data["reasoning"]
    data["confidence"] = data["confidence"].to_i if data["confidence"].is_a?(String) && data["confidence"].match?(/^\d+$/)
    data["requires_human_approval"] = data["requires_human_review"] if data["requires_human_approval"].nil?
    data["requires_human_review"] = data["requires_human_approval"] if data["requires_human_review"].nil?
    data["recommended_action"] ||= data["recommended_steps"].is_a?(Array) ? data["recommended_steps"].join(", ") : nil
    data["draft_response"] ||= data["reasoning"]

    # Evidence normalization
    data["evidence"] ||= data["evidence_refs"] || data[:evidence] || []
    if data["evidence"].is_a?(Array) && data["evidence"].first.is_a?(Hash)
      data["evidence"] = data["evidence"].map { |e| e["description"] || e[:description] || e.to_s }
    end
    data["evidence"] = [data["evidence"].to_s] unless data["evidence"].is_a?(Array)

    # Matched runbook normalization
    data["matched_runbook"] ||= data["source_refs"] || data[:matched_runbook]
    if data["matched_runbook"].is_a?(Array) && data["matched_runbook"].any?
      first_ref = data["matched_runbook"].first
      data["matched_runbook"] = first_ref.is_a?(Hash) ? (first_ref["quote"] || first_ref[:quote] || first_ref.to_s) : first_ref.to_s
    elsif data["matched_runbook"].blank?
      data["matched_runbook"] = "No matching runbook found in knowledge base"
    end

    REQUIRED_KEYS.each do |key|
      unless data.key?(key) && data[key] != nil
        @errors << "Missing required key '#{key}'"
      end
    end

    severity = data["severity"].to_s.downcase
    unless %w[low medium high critical].include?(severity)
      @errors << "'severity' must be one of low, medium, high, critical"
    end

    conf = data["confidence"]
    unless conf.is_a?(Numeric) && conf >= 0 && conf <= 100
      @errors << "'confidence' must be a number between 0 and 100"
    end

    unless [true, false].include?(data["requires_human_approval"])
      @errors << "'requires_human_approval' must be a boolean"
    end

    if @errors.any?
      raise ValidationError, "Ticket analysis schema validation failed: #{@errors.join('; ')}"
    end

    data.deep_stringify_keys
  end

  private

  def parse_payload(raw)
    return raw if raw.is_a?(Hash)
    return JSON.parse(raw) if raw.is_a?(String)

    raise ValidationError, "Expected Hash or JSON string, got #{raw.class.name}"
  rescue JSON::ParserError => e
    raise ValidationError, "Malformed JSON response: #{e.message}"
  end
end
