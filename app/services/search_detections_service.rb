class SearchDetectionsService
  def initialize(params = {}, current_user: nil)
    @params = params
    @current_user = current_user
  end

  def call
    scope = Detection.includes(:assigned_to, :evidences).all

    if @params[:query].present?
      q = "%#{@params[:query].to_s.strip.downcase}%"
      scope = scope.where(
        "LOWER(title) LIKE :q OR LOWER(hostname) LIKE :q OR LOWER(process_name) LIKE :q OR LOWER(ip_address) LIKE :q",
        q: q
      )
    end

    if @params[:severity].present? && @params[:severity] != "all"
      scope = scope.where(severity: @params[:severity])
    end

    if @params[:status].present? && @params[:status] != "all"
      scope = scope.where(status: @params[:status])
    end

    if @params[:sla_risk].present? && @params[:sla_risk].to_s == "true"
      scope = scope.where(sla_risk: true)
    end

    scope.recent_first
  end
end
