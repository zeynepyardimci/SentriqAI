class InvestigationSchemaValidator
  class ValidationError < StandardError; end

  REQUIRED_KEYS = %w[
    summary
    observed_evidence
    possible_causes
    evidence_gaps
    recommended_steps
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

    summary = data["summary"] || data[:summary]
    if summary.blank? || !summary.is_a?(String)
      @errors << "'summary' must be a non-empty string"
    end

    %w[observed_evidence possible_causes evidence_gaps recommended_steps].each do |array_key|
      val = data[array_key] || data[array_key.to_sym]
      unless val.is_a?(Array)
        @errors << "'#{array_key}' must be an array"
      end
    end

    human_rev = data["requires_human_review"].nil? ? data[:requires_human_review] : data["requires_human_review"]
    unless [true, false].include?(human_rev)
      @errors << "'requires_human_review' must be a boolean"
    end

    if @errors.any?
      raise ValidationError, "Investigation output validation failed: #{@errors.join('; ')}"
    end

    # Return normalized hash with string keys
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
