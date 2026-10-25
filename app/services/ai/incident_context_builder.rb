# frozen_string_literal: true

require "digest"

module Ai
  class IncidentContextBuilder
    attr_reader :ticket, :detection, :current_user

    def initialize(ticket: nil, detection: nil, current_user: nil)
      @ticket = ticket.is_a?(Ticket) ? ticket : (Ticket.find_by(id: ticket) if ticket.present?)
      @detection = detection.is_a?(Detection) ? detection : (Detection.find_by(id: detection) if detection.present?)
      @detection ||= @ticket&.detection
      @ticket ||= @detection&.tickets&.recent_first&.first
      @current_user = current_user
    end

    def build
      raw_telemetry = extract_telemetry
      evidences_list = extract_evidences
      missing = detect_missing_fields(raw_telemetry, evidences_list)
      prior_events = find_prior_related_events(raw_telemetry)
      prior_notes = extract_prior_notes

      incident_type = classify_incident_archetype(raw_telemetry)

      context_data = {
        ticket: {
          id: @ticket&.id,
          ticket_number: @ticket&.ticket_number,
          title: @ticket&.title,
          description: @ticket&.description,
          priority: @ticket&.priority,
          status: @ticket&.status,
          assigned_agent: @ticket&.assigned_agent,
          created_at: @ticket&.created_at&.iso8601
        },
        detection: {
          id: @detection&.id,
          title: @detection&.title,
          description: @detection&.description,
          severity: @detection&.severity,
          status: @detection&.status,
          triggered_at: @detection&.triggered_at&.iso8601,
          sla_risk: @detection&.sla_risk || false,
          sla_breached_at: @detection&.sla_breached_at&.iso8601
        },
        telemetry: raw_telemetry,
        evidences: evidences_list,
        missing_fields: missing,
        prior_related_events: prior_events,
        prior_notes: prior_notes,
        incident_type: incident_type
      }

      hashable_payload = {
        ticket_id: @ticket&.id,
        ticket_title: @ticket&.title,
        ticket_description: @ticket&.description,
        detection_id: @detection&.id,
        detection_title: @detection&.title,
        detection_desc: @detection&.description,
        telemetry: raw_telemetry,
        evidences: evidences_list,
        missing_fields: missing,
        incident_type: incident_type
      }

      context_hash = Digest::SHA256.hexdigest(hashable_payload.to_json)
      context_data[:context_hash] = context_hash
      context_data[:built_at] = Time.current.iso8601

      context_data
    end

    private

    def extract_telemetry
      {
        hostname: @detection&.hostname || @ticket&.context_metadata&.dig("hostname") || @ticket&.context_metadata&.dig(:hostname),
        ip_address: @detection&.ip_address || @ticket&.context_metadata&.dig("ip_address") || @ticket&.context_metadata&.dig(:ip_address),
        username: @detection&.username || @ticket&.context_metadata&.dig("username") || @ticket&.context_metadata&.dig(:username),
        process_name: @detection&.process_name || @ticket&.context_metadata&.dig("process_name") || @ticket&.context_metadata&.dig(:process_name),
        process_id: @detection&.process_id,
        parent_process_name: @detection&.parent_process_name,
        parent_process_id: @detection&.parent_process_id,
        command_line: @detection&.command_line || @ticket&.context_metadata&.dig("command_line") || @ticket&.context_metadata&.dig(:command_line),
        file_path: @detection&.file_path,
        file_hash: @detection&.file_hash,
        raw_edr_metadata: @detection&.raw_telemetry || {}
      }
    end

    def extract_evidences
      return [] unless @detection
      @detection.evidences.chronological.map do |ev|
        {
          id: ev.id,
          evidence_type: ev.evidence_type,
          occurred_at: ev.occurred_at.iso8601,
          description: ev.description,
          details: ev.details || {}
        }
      end
    end

    def detect_missing_fields(telem, evidences)
      gaps = []
      gaps << "process_name" if telem[:process_name].blank?
      gaps << "command_line" if telem[:command_line].blank?
      gaps << "parent_process" if telem[:parent_process_name].blank?
      gaps << "file_hash" if telem[:file_hash].blank?
      gaps << "ip_address" if telem[:ip_address].blank?
      gaps << "network_telemetry" unless evidences.any? { |e| e[:evidence_type].to_s.include?("network") }
      gaps << "file_activity_telemetry" unless evidences.any? { |e| e[:evidence_type].to_s.include?("file") }
      gaps << "user_context" if telem[:username].blank?
      gaps
    end

    def find_prior_related_events(telem)
      return [] unless @detection || telem[:hostname].present?

      scope = Detection.where.not(id: @detection&.id)
      conditions = []
      conditions << scope.where(hostname: telem[:hostname]) if telem[:hostname].present?
      conditions << scope.where(file_hash: telem[:file_hash]) if telem[:file_hash].present?

      related = conditions.reduce(:or)&.recent_first&.limit(3) || Detection.none
      related.map do |d|
        {
          id: d.id,
          title: d.title,
          severity: d.severity,
          status: d.status,
          triggered_at: d.triggered_at.iso8601
        }
      end
    end

    def extract_prior_notes
      notes = []
      if @ticket
        @ticket.ticket_notes.where.not(note_type: "analysis_draft").chronological.limit(5).each do |n|
          notes << {
            author: n.author_name,
            author_type: n.author_type,
            note_type: n.note_type,
            body: n.body.truncate(160),
            created_at: n.created_at.iso8601
          }
        end
      end
      notes
    end

    def classify_incident_archetype(telem)
      combined_text = [
        @ticket&.title,
        @ticket&.description,
        @detection&.title,
        @detection&.description,
        telem[:command_line],
        telem[:process_name]
      ].compact.join(" ").downcase

      if combined_text.include?("tatbikat") || combined_text.include?("drill") || combined_text.include?("retrospective") || combined_text.include?("tamamland")
        :drill_or_retrospective
      elsif combined_text.include?("vssadmin") || combined_text.include?("shadow") || combined_text.include?("ransom")
        :ransomware_precursor
      elsif combined_text.include?("powershell") || combined_text.include?("-enc") || combined_text.include?("encodedcommand")
        :suspicious_powershell_lolbin
      elsif combined_text.include?("certutil") || combined_text.include?("urlcache")
        :lolbin_ingress
      elsif combined_text.include?("lsass") || combined_text.include?("mimikatz") || combined_text.include?("credential")
        :credential_dumping
      elsif combined_text.include?("emin de") || combined_text.include?("belirsiz") || combined_text.include?("çelişkili")
        :ambiguous_or_conflicting
      else
        :generic_security_event
      end
    end
  end
end
