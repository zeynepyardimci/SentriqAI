# frozen_string_literal: true

module Api
  module V1
    class AutonomousAgentsController < BaseController
      # POST /api/v1/agent/autonomous_ingest
      def ingest
        detection = Detection.find_by(id: params[:detection_id]) if params[:detection_id].present?
        all_unhandled = ActiveModel::Type::Boolean.new.cast(params[:all_unhandled])
        human_gate = params[:human_gate].nil? ? false : ActiveModel::Type::Boolean.new.cast(params[:human_gate])

        service = AutonomousAgentDispatcherService.new(
          detection: detection,
          all_unhandled: all_unhandled,
          current_user: current_agent_user,
          human_gate: human_gate
        )

        outcome = service.call

        if outcome[:success]
          render json: {
            success: true,
            message: "Autonomous agent completed zero-touch triage for #{outcome[:processed_count]} event(s).",
            processed_count: outcome[:processed_count],
            results: outcome[:results].map do |res|
              {
                ticket_id: res[:ticket].id,
                ticket_number: res[:ticket].ticket_number,
                title: res[:ticket].title,
                status: res[:status],
                priority: res[:ticket].priority,
                outcome: res[:outcome],
                detection_id: res[:detection_id],
                intent: res[:analysis]&.dig("intent"),
                confidence: res[:analysis]&.dig("confidence"),
                recommended_action: res[:analysis]&.dig("recommended_action"),
                requires_human_review: res[:analysis]&.dig("requires_human_review")
              }
            end,
            logs: outcome[:logs]
          }, status: :ok
        else
          render json: {
            success: false,
            error: outcome[:error],
            logs: outcome[:logs]
          }, status: :unprocessable_entity
        end
      end
    end
  end
end
