class AuditEventsController < ApplicationController
  def index
    @audit_events = AuditEvent.includes(:user, :trackable).recent_first.limit(100)
  end
end
