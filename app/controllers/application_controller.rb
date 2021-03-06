class ApplicationController < ActionController::Base
    before_action :authenticate_user!
    
    protect_from_forgery with: :exception

    before_action :configure_permitted_params, if: :devise_controller?

    protected

    def configure_permitted_params
        devise_parameter_sanitizer.permit(:sign_up, keys:[:name, :email, :phone_number])
        devise_parameter_sanitizer.permit(:account_update, keys:[:name, :email, :phone_number, :avatar])
    end
end
