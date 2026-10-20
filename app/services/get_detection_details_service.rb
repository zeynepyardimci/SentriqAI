class GetDetectionDetailsService
  class DetectionNotFoundError < StandardError; end

  def initialize(detection_id, current_user: nil)
    @detection_id = detection_id
    @current_user = current_user
  end

  def call
    detection = Detection.includes(:evidences, :assigned_to, investigations: [:source_references, :investigation_notes]).find_by(id: @detection_id)
    raise DetectionNotFoundError, "Detection with ID #{@detection_id} not found" unless detection

    {
      detection: detection,
      evidences: detection.evidences.chronological,
      investigations: detection.investigations.recent_first,
      audit_events: detection.audit_events.recent_first,
      sla_status: {
        is_at_risk: detection.sla_risk?,
        breached_at: detection.sla_breached_at,
        elapsed_minutes: ((Time.current - detection.triggered_at) / 60.0).round(1)
      }
    }
  end
end
