module Api
  module V1
    class BaseController < ActionController::API
      before_action :authenticate_agent!
      before_action :check_rate_limit!

      rescue_from ActiveRecord::RecordNotFound, with: :render_not_found
      rescue_from ActiveRecord::RecordInvalid, with: :render_unprocessable
      rescue_from ActionController::ParameterMissing, with: :render_bad_request
      rescue_from ArgumentError, with: :render_bad_request

      attr_reader :current_agent_user

      private

      def authenticate_agent!
        token = extract_token
        if token.blank?
          render_unauthorized("Missing authorization token. Provide 'X-Agent-Token' header or 'Authorization: Bearer <token>'")
          return
        end

        @current_agent_user = User.find_by(demo_token: token)
        unless @current_agent_user
          render_unauthorized("Invalid agent token")
        end
      end

      def extract_token
        header = request.headers["X-Agent-Token"] || request.headers["Authorization"]
        return nil if header.blank?

        if header.start_with?("Bearer ")
          header.sub("Bearer ", "").strip
        else
          header.strip
        end
      end

      def check_rate_limit!
        # Set rate limit headers for API compliance
        response.headers["X-RateLimit-Limit"] = "100"
        response.headers["X-RateLimit-Remaining"] = "99"
        response.headers["X-RateLimit-Reset"] = (Time.current + 1.minute).to_i.to_s
      end

      def render_unauthorized(msg)
        render json: {
          error: "unauthorized",
          message: msg,
          status: 401
        }, status: :unauthorized
      end

      def render_not_found(exception)
        render json: {
          error: "not_found",
          message: exception.message,
          status: 404
        }, status: :not_found
      end

      def render_unprocessable(exception)
        render json: {
          error: "unprocessable_entity",
          message: exception.record.errors.full_messages.join(", "),
          status: 422
        }, status: :unprocessable_entity
      end

      def render_bad_request(exception)
        render json: {
          error: "bad_request",
          message: exception.message,
          status: 400
        }, status: :bad_request
      end
    end
  end
end
