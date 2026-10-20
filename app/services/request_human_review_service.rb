class RequestHumanReviewService
  def initialize(detection:, user:, action:, note_body: nil)
    @detection = detection.is_a?(Detection) ? detection : Detection.find(detection)
    @user = user
    @action = action.to_s # 'escalate_to_lead', 'approve_and_solve', 'request_changes'
    @note_body = note_body
  end

  def call
    ActiveRecord::Base.transaction do
      case @action
      when "escalate_to_lead"
        if @detection.status == "investigating"
          @detection.transition_to!("pending_review", user: @user, reason: "Escalated for senior analyst / lead review")
        end
        note_type = "escalation"
      when "approve_and_solve"
        if @detection.status == "investigating"
          @detection.transition_to!("pending_review", user: @user, reason: "Ready for solution")
        end
        if @detection.status == "pending_review"
          @detection.transition_to!("solved", user: @user, reason: "Analyst reviewed and confirmed resolution")
        end
        note_type = "approval"
      when "request_changes"
        if @detection.status == "pending_review"
          @detection.transition_to!("investigating", user: @user, reason: "Sent back for deeper evidence gathering")
        end
        note_type = "correction"
      when "reopen"
        if @detection.status == "solved"
          @detection.transition_to!("reopened", user: @user, reason: "Reopened by analyst due to new alerts")
        end
        note_type = "analyst_comment"
      else
        raise ArgumentError, "Unknown human review action: #{@action}"
      end

      # Add note to latest investigation if exists
      latest_investigation = @detection.investigations.recent_first.first
      if latest_investigation && @note_body.present?
        latest_investigation.investigation_notes.create!(
          user: @user,
          note_type: note_type,
          body: @note_body
        )
      end

      AuditEvent.create!(
        trackable: @detection,
        user: @user,
        action: "human_review_#{@action}",
        details: {
          action: @action,
          note: @note_body,
          new_status: @detection.status
        }
      )

      @detection
    end
  end
end
