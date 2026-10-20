class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  helper_method :current_user, :logged_in?

  before_action :set_current_user

  private

  def set_current_user
    if session[:user_id].present?
      @current_user = User.find_by(id: session[:user_id])
    elsif params[:demo_token].present?
      @current_user = User.find_by(demo_token: params[:demo_token])
      session[:user_id] = @current_user.id if @current_user
    end

    # Default to first analyst for frictionless controlled demo access if no session
    @current_user ||= User.find_by(role: "analyst") || User.first
  end

  def current_user
    @current_user
  end

  def logged_in?
    @current_user.present?
  end
end
