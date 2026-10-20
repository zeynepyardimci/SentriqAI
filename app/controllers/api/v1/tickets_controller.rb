module Api
  module V1
    class TicketsController < BaseController
      before_action :set_ticket, only: [:show, :analyze, :add_note, :escalate, :human_decision]

      # POST /api/v1/tickets
      def create
        idempotency_key = request.headers["Idempotency-Key"].presence || params[:idempotency_key].presence

        if idempotency_key.present?
          existing = Ticket.find_by(idempotency_key: idempotency_key)
          if existing
            response.headers["X-Idempotent-Replay"] = "true"
            render json: serialize_ticket(existing), status: :ok
            return
          end
        end

        detection = Detection.find_by(id: params[:detection_id]) if params[:detection_id].present?

        ticket = Ticket.new(
          title: params.require(:title),
          description: params.require(:description),
          priority: params[:priority] || (detection&.severity || "medium"),
          status: "open",
          assigned_agent: params[:assigned_agent] || current_agent_user.name,
          idempotency_key: idempotency_key,
          detection: detection,
          user: current_agent_user,
          context_metadata: params[:context_metadata] || {}
        )

        ticket.save!

        AuditEvent.create!(
          trackable: ticket,
          user: current_agent_user,
          action: "ticket_created_via_api",
          details: {
            assigned_agent: ticket.assigned_agent,
            detection_id: ticket.detection_id,
            idempotency_key: idempotency_key
          }
        )

        render json: serialize_ticket(ticket), status: :created
      end

      # GET /api/v1/tickets/:id
      def show
        render json: serialize_ticket(@ticket, detailed: true), status: :ok
      end

      # POST /api/v1/tickets/:id/analyze
      def analyze
        result = TicketContextualAnalyzerService.new(ticket: @ticket, current_user: current_agent_user).call

        render json: {
          ticket_id: @ticket.id,
          ticket_number: @ticket.ticket_number,
          status: @ticket.status,
          llm_analysis: result[:analysis],
          agent_mode: result[:agent_mode]
        }, status: :ok
      end

      # POST /api/v1/tickets/:id/notes
      def add_note
        body = params.require(:body)
        note_type = params[:note_type] || "finding"
        author_name = params[:author_name].presence || current_agent_user.name

        note = @ticket.ticket_notes.create!(
          user: current_agent_user,
          author_type: "agent",
          author_name: author_name,
          note_type: note_type,
          body: body,
          metadata: params[:metadata] || {}
        )

        AuditEvent.create!(
          trackable: @ticket,
          user: current_agent_user,
          action: "ticket_note_added_via_api",
          details: { note_id: note.id, note_type: note_type }
        )

        render json: {
          note_id: note.id,
          ticket_id: @ticket.id,
          note_type: note.note_type,
          body: note.body,
          created_at: note.created_at.iso8601
        }, status: :created
      end

      # POST /api/v1/tickets/:id/escalate
      def escalate
        reason = params[:reason].presence || "Escalated for human analyst triage via API"
        @ticket.escalate_to_human!(reason: reason, user: current_agent_user)

        render json: {
          ticket_id: @ticket.id,
          ticket_number: @ticket.ticket_number,
          status: @ticket.status,
          message: "Ticket escalated to pending_review for human analyst review"
        }, status: :ok
      end

      # GET /api/v1/tickets/:id/human_decision
      def human_decision
        render json: {
          ticket_id: @ticket.id,
          ticket_number: @ticket.ticket_number,
          status: @ticket.status,
          human_decision: @ticket.human_decision,
          human_decision_notes: @ticket.human_decision_notes,
          human_reviewer: @ticket.human_reviewer ? { id: @ticket.human_reviewer.id, name: @ticket.human_reviewer.name, role: @ticket.human_reviewer.role } : nil,
          human_reviewed_at: @ticket.human_reviewed_at&.iso8601
        }, status: :ok
      end

      private

      def set_ticket
        @ticket = Ticket.find(params[:id])
      end

      def serialize_ticket(t, detailed: false)
        data = {
          id: t.id,
          ticket_number: t.ticket_number,
          title: t.title,
          description: t.description,
          status: t.status,
          priority: t.priority,
          assigned_agent: t.assigned_agent,
          idempotency_key: t.idempotency_key,
          detection_id: t.detection_id,
          created_at: t.created_at.iso8601,
          updated_at: t.updated_at.iso8601
        }

        if detailed
          data[:detection] = if t.detection
            {
              id: t.detection.id,
              title: t.detection.title,
              hostname: t.detection.hostname,
              process_name: t.detection.process_name,
              command_line: t.detection.command_line,
              severity: t.detection.severity,
              status: t.detection.status,
              evidences_count: t.detection.evidences.count
            }
          end
          data[:llm_analysis] = t.llm_analysis
          data[:notes] = t.ticket_notes.chronological.map do |n|
            {
              id: n.id,
              author_name: n.author_name,
              author_type: n.author_type,
              note_type: n.note_type,
              body: n.body,
              created_at: n.created_at.iso8601
            }
          end
          data[:human_decision] = {
            decision: t.human_decision,
            notes: t.human_decision_notes,
            reviewed_at: t.human_reviewed_at&.iso8601,
            reviewer_name: t.human_reviewer&.name
          }
        end

        data
      end
    end
  end
end
