# frozen_string_literal: true

class CheckSlaJob < ApplicationJob
  queue_as :default

  def perform
    now = Time.current

    # Check detections
    Detection.where(status: %w[new open]).where(severity: %w[high critical]).find_each do |det|
      det.check_sla!(now)
    end

    # Check tickets
    Ticket.where(status: %w[open investigating]).where(priority: %w[high critical]).find_each do |ticket|
      ticket.check_sla!(now)
    end
  end
end
