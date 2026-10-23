Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  root to: "detections#index"

  resources :detections, only: [:index, :show] do
    member do
      post :investigate
      post :review
      post :add_note
      post :auto_ticket
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
      post :autonomous_ingest
    end
  end

  resources :knowledge_documents, only: [:index, :show]
  resource :session, only: [:new, :create, :destroy]
  get "audit_trail", to: "audit_events#index"

  # Page-Agent In-Page GUI & Ragie RAG Endpoints
  post "page_agent/execute", to: "page_agent#execute"
  post "page_agent/ragie_search", to: "page_agent#ragie_search"
  post "page_agent/set_api_key", to: "page_agent#set_api_key"

  # Agent-First REST API v1
  namespace :api do
    namespace :v1 do
      post "agent/autonomous_ingest", to: "autonomous_agents#ingest"

      resources :tickets, only: [:create, :show] do
        member do
          post :analyze
          post :notes, to: "tickets#add_note"
          post :escalate
          get :human_decision
          post :human_decision, to: "tickets#apply_human_decision"
        end
      end

      resources :detections, only: [:index, :show]
      get "knowledge_base/search", to: "knowledge_base#search"
    end
  end
end
