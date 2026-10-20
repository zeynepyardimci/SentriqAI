class SearchKnowledgeBaseService
  STOP_WORDS = %w[
    execution utility detection alert suspicious tool file process
    running event test incident report system check host
  ].freeze

  def initialize(query, limit: 5, current_user: nil)
    @query = query.to_s.strip
    @limit = [[limit.to_i, 1].max, 10].min
    @current_user = current_user
  end

  def call
    return empty_result("Query is empty") if @query.blank?

    tokens = extract_meaningful_tokens(@query)
    return empty_result("No discriminative search tokens extracted from '#{@query}'") if tokens.empty?

    chunks = KnowledgeChunk.includes(:knowledge_document).search(tokens.join(" "), limit: @limit)

    if chunks.empty?
      return {
        success: true,
        matched: false,
        results: [],
        message: "No matching knowledge document found for '#{@query}'"
      }
    end

    results = chunks.map do |chunk|
      doc = chunk.knowledge_document
      {
        chunk_id: chunk.id,
        chunk_index: chunk.chunk_index,
        document_id: doc.id,
        document_title: doc.title,
        category: doc.category,
        external_reference: doc.external_reference,
        quote: chunk.chunk_text,
        sanitized_content: sanitize_chunk_for_prompt(chunk.chunk_text)
      }
    end

    {
      success: true,
      matched: true,
      results: results,
      message: "#{results.size} knowledge chunk(s) retrieved"
    }
  end

  private

  def extract_meaningful_tokens(raw)
    raw.downcase.gsub(/[^a-z0-9_\-]/, " ")
       .split
       .reject { |t| t.length < 4 || STOP_WORDS.include?(t) }
  end

  def empty_result(msg)
    {
      success: true,
      matched: false,
      results: [],
      message: msg
    }
  end

  def sanitize_chunk_for_prompt(text)
    sanitized = text.gsub("```", "'''")
    sanitized.gsub(/(ignore\s+all\s+previous\s+instructions|system\s+prompt|delete\s+all|override\s+rules)/i, "[DISARMED_UNTRUSTED_INSTRUCTION]")
  end
end
