# frozen_string_literal: true

class TicketContextualAnalyzerService
  def initialize(ticket:, current_user: nil, force_reanalyze: false)
    @ticket = ticket.is_a?(Ticket) ? ticket : Ticket.find(ticket)
    @current_user = current_user
    @force_reanalyze = force_reanalyze
  end

  def call
    # Delegate to the centralized AI Orchestrator middleware layer
    result = Ai::Orchestrator.call(
      ticket: @ticket,
      detection: @ticket.detection,
      current_user: @current_user,
      force_reanalyze: @force_reanalyze
    )

    {
      success: result[:success],
      ticket: @ticket.reload,
      analysis: result[:analysis],
      agent_mode: result[:agent_mode],
      confidence_assessment: result[:confidence_assessment]
    }
  end
end
