module Api
  module V1
    class DetectionsController < BaseController
      def index
        detections = SearchDetectionsService.new(params, current_user: current_agent_user).call.limit(25)

        render json: {
          count: detections.size,
          detections: detections.map do |d|
            {
              id: d.id,
              title: d.title,
              severity: d.severity,
              status: d.status,
              hostname: d.hostname,
              ip_address: d.ip_address,
              process_name: d.process_name,
              command_line: d.command_line,
              file_hash: d.file_hash,
              sla_risk: d.sla_risk?,
              triggered_at: d.triggered_at.iso8601,
              evidences: d.evidences.chronological.map do |ev|
                {
                  id: ev.id,
                  type: ev.evidence_type,
                  occurred_at: ev.occurred_at.iso8601,
                  description: ev.description
                }
              end
            }
          end
        }, status: :ok
      end

      def show
        detection = Detection.find(params[:id])
        render json: {
          id: detection.id,
          title: detection.title,
          description: detection.description,
          severity: detection.severity,
          status: detection.status,
          hostname: detection.hostname,
          process_name: detection.process_name,
          parent_process_name: detection.parent_process_name,
          command_line: detection.command_line,
          file_hash: detection.file_hash,
          triggered_at: detection.triggered_at.iso8601,
          evidences: detection.evidences.chronological.map do |ev|
            {
              id: ev.id,
              type: ev.evidence_type,
              occurred_at: ev.occurred_at.iso8601,
              description: ev.description,
              details: ev.details
            }
          end
        }, status: :ok
      end
    end
  end
end
