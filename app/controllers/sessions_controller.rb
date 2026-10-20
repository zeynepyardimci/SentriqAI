class SessionsController < ApplicationController
  def new
    @users = User.order(:name)
  end

  def create
    user = User.find_by(id: params[:user_id])
    if user
      session[:user_id] = user.id
      flash[:notice] = "Switched persona to #{user.name} (#{user.role.humanize})."
    end
    redirect_to root_path
  end

  def destroy
    session[:user_id] = nil
    flash[:notice] = "Session reset to default demo analyst."
    redirect_to root_path
  end
end
