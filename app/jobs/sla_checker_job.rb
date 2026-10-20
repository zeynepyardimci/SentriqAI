class SlaCheckerJob < ApplicationJob
  queue_as :default

  def perform
    SlaCheckerService.run!
  end
end
