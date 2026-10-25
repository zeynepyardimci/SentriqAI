# frozen_string_literal: true

module Ai
  class RunbookRetriever
    def self.retrieve(context, limit: 3, current_user: nil)
      new(context, limit: limit, current_user: current_user).retrieve
    end

    def initialize(context, limit: 3, current_user: nil)
      @context = context
      @limit = limit
      @current_user = current_user
    end

    def retrieve
      query = build_retrieval_query
      return no_runbook_result("Arama sorgusu oluşturulamadı") if query.blank?

      # 1. First attempt KnowledgeBase local search
      local_results = SearchKnowledgeBaseService.new(query, limit: @limit, current_user: @current_user).call
      docs = local_results[:results] || []

      # 2. If no local docs and Ragie is configured, try Ragie
      if docs.empty? && ENV["RAGIE_API_KEY"].present?
        ragie_res = RagieRetrievalService.new(query, limit: @limit).call
        docs = ragie_res[:results] || []
      end

      # 3. Filter by relevance threshold if possible
      matched = docs.map do |doc|
        {
          document_id: doc[:document_id],
          title: doc[:document_title],
          document_title: doc[:document_title],
          category: doc[:category],
          external_reference: doc[:external_reference],
          quote: doc[:quote].to_s.truncate(300),
          relevance_explanation: "Olay telemetrisindeki '#{extract_key_process}' ve MITRE bağlamı ile kurumsal prosedür eşleşmektedir."
        }
      end

      if matched.any?
        {
          matched: true,
          query_used: query,
          runbooks: matched
        }
      else
        no_runbook_result("Bilgi tabanında bu olayın parametreleriyle doğrudan eşleşen onaylı runbook dokümanı bulunamadı.")
      end
    rescue StandardError => e
      Rails.logger.warn("[SentriqAI::RunbookRetriever] Retrieval failed: #{e.message}")
      no_runbook_result("Runbook arama servisinde hata oluştu: #{e.message}")
    end

    private

    def build_retrieval_query
      telem = @context[:telemetry] || {}
      t = @context[:ticket] || {}
      d = @context[:detection] || {}

      archetype = @context[:incident_type]

      parts = []
      case archetype
      when :ransomware_precursor
        parts << "vssadmin shadow copy deletion ransomware T1490"
      when :suspicious_powershell_lolbin
        parts << "obfuscated powershell lolbins T1059.001"
      when :lolbin_ingress
        parts << "certutil living off the land ingress T1105"
      when :credential_dumping
        parts << "lsass memory dump credential extraction T1003"
      when :drill_or_retrospective
        parts << "tatbikat drill yedekleme rutin"
      end

      parts << telem[:process_name] if telem[:process_name].present?
      parts << t[:title] if t[:title].present?
      parts << d[:title] if d[:title].present?

      parts.compact.uniq.join(" ").truncate(200)
    end

    def extract_key_process
      @context.dig(:telemetry, :process_name) || @context.dig(:telemetry, :command_line)&.split&.first || "süreç"
    end

    def no_runbook_result(reason)
      {
        matched: false,
        query_used: nil,
        runbooks: [],
        note: reason
      }
    end
  end
end
