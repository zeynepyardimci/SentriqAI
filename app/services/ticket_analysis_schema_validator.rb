class TicketAnalysisSchemaValidator
  class ValidationError < StandardError; end

  REQUIRED_KEYS = %w[
    intent
    priority
    recommended_action
    draft_response
    rationale
    confidence
    requires_human_review
  ].freeze

  def self.validate(payload)
    new(payload).validate!
  end

  def initialize(payload)
    @payload = payload
    @errors = []
  end

  def validate!
    data = parse_payload(@payload)

    REQUIRED_KEYS.each do |key|
      unless data.key?(key) || data.key?(key.to_sym)
        @errors << "Missing required key '#{key}'"
      end
    end

    intent = data["intent"] || data[:intent]
    if intent.blank? || !intent.is_a?(String)
      @errors << "'intent' must be a non-empty string"
    end

    priority = (data["priority"] || data[:priority]).to_s.downcase
    unless %w[low medium high critical].include?(priority)
      @errors << "'priority' must be one of low, medium, high, critical"
    end

    conf = data["confidence"] || data[:confidence]
    unless conf.is_a?(Numeric) && conf >= 0 && conf <= 100
      @errors << "'confidence' must be a number between 0 and 100"
    end

    human_rev = data["requires_human_review"].nil? ? data[:requires_human_review] : data["requires_human_review"]
    unless [true, false].include?(human_rev)
      @errors << "'requires_human_review' must be a boolean"
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
