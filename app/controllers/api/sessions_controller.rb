class Api::SessionsController < ApplicationController
  def create
    @user = User.find_by_credentials(params[:user][:username], params[:user][:password])
    if @user
      login(user)
      render '/api/user/show'
    else
      # flash[:errors] = @user.errors.full_messages
      render json: ['invalid credentials'], :status => 422
    end
  end

  def destroy
    if current_user
      logout
      render json: {}, :status => 200
    else
      render json: [], :status => 404
    end
  end
end
