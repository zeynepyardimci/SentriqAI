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

  resources :tickets, only: [:index, :show] do
    member do
      post :review
      post :add_note
    end
    collection do
      get :demo
      post :trigger_agent_flow
    end
  end

  resources :knowledge_documents, only: [:index, :show]
  resource :session, only: [:new, :create, :destroy]
  get "audit_trail", to: "audit_events#index"

  # Agent-First REST API v1
  namespace :api do
    namespace :v1 do
      resources :tickets, only: [:create, :show] do
        member do
          post :analyze
          post :notes, to: "tickets#add_note"
          post :escalate
          get :human_decision
        end
      end

      resources :detections, only: [:index, :show]
      get "knowledge_base/search", to: "knowledge_base#search"
    end
  end
end
