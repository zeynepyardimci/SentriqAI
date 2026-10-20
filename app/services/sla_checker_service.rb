class SlaCheckerService
  def self.run!(current_time = Time.current)
    new(current_time).run!
  end

  def initialize(current_time = Time.current)
    @current_time = current_time
  end

  def run!
    candidates = Detection.where(severity: %w[high critical], sla_risk: false)
                          .where.not(status: %w[investigating pending_review solved])

    flagged = []
    candidates.find_each do |det|
      old_risk = det.sla_risk?
      det.check_sla!(@current_time)
      flagged << det if !old_risk && det.sla_risk?
    end

    {
      checked_count: candidates.count,
      flagged_count: flagged.size,
      flagged_detections: flagged
    }
  end
end
