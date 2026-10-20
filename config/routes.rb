Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  root to: "detections#index"

  resources :detections, only: [:index, :show] do
    member do
      post :investigate
      post :review
      post :add_note
    end
    collection do
      post :check_sla
    end
  end

  resources :knowledge_documents, only: [:index, :show]
  resource :session, only: [:new, :create, :destroy]
  get "audit_trail", to: "audit_events#index"
end
