module Api
  module V1
    class KnowledgeBaseController < BaseController
      def search
        query = params[:query].to_s.strip
        limit = params[:limit] || 5

        result = SearchKnowledgeBaseService.new(query, limit: limit, current_user: current_agent_user).call

        render json: {
          query: query,
          matched: result[:matched],
          count: (result[:results] || []).size,
          results: result[:results] || [],
          message: result[:message]
        }, status: :ok
      end
    end
  end
end
