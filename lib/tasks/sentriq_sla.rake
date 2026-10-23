# frozen_string_literal: true

namespace :sentriq do
  desc "Check SLA thresholds for open high/critical detections and tickets and escalate if breached"
  task check_sla: :environment do
    puts "[Sentriq AI] Starting SLA threshold verification at #{Time.current}..."
    CheckSlaJob.perform_now
    puts "[Sentriq AI] SLA check completed."
  end
end
