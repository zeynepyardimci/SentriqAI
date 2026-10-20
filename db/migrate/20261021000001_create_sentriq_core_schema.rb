class CreateSentriqCoreSchema < ActiveRecord::Migration[8.1]
  def change
    # Enable pgvector if available
    enable_extension "vector" rescue nil

    create_table :users do |t|
      t.string :email, null: false
      t.string :name, null: false
      t.string :role, null: false, default: "analyst"
      t.string :demo_token, null: false
      t.string :password_digest
      t.timestamps
    end
    add_index :users, :email, unique: true
    add_index :users, :demo_token, unique: true

    create_table :detections do |t|
      t.string :title, null: false
      t.text :description
      t.string :severity, null: false, default: "medium"
      t.string :status, null: false, default: "new"
      t.string :hostname, null: false
      t.string :ip_address
      t.string :username
      t.string :process_name
      t.integer :process_id
      t.string :parent_process_name
      t.integer :parent_process_id
      t.text :command_line
      t.string :file_path
      t.string :file_hash
      t.datetime :triggered_at, null: false
      t.boolean :sla_risk, null: false, default: false
      t.datetime :sla_breached_at
      t.references :assigned_to, foreign_key: { to_table: :users }
      t.jsonb :raw_telemetry, default: {}
      t.timestamps
    end
    add_index :detections, :status
    add_index :detections, :severity
    add_index :detections, :triggered_at
    add_index :detections, :sla_risk

    create_table :evidences do |t|
      t.references :detection, null: false, foreign_key: true
      t.string :evidence_type, null: false
      t.datetime :occurred_at, null: false
      t.text :description, null: false
      t.jsonb :details, default: {}
      t.timestamps
    end
    add_index :evidences, [:detection_id, :occurred_at]

    create_table :knowledge_documents do |t|
      t.string :title, null: false
      t.string :category, null: false
      t.string :external_reference
      t.text :content, null: false
      t.jsonb :metadata, default: {}
      t.timestamps
    end
    add_index :knowledge_documents, :category

    create_table :knowledge_chunks do |t|
      t.references :knowledge_document, null: false, foreign_key: true
      t.integer :chunk_index, null: false
      t.text :chunk_text, null: false
      t.string :keywords
      t.timestamps
    end
    add_index :knowledge_chunks, [:knowledge_document_id, :chunk_index], unique: true

    create_table :investigations do |t|
      t.references :detection, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :status, null: false, default: "completed"
      t.text :summary, null: false
      t.jsonb :observed_evidence, default: []
      t.jsonb :possible_causes, default: []
      t.jsonb :evidence_gaps, default: []
      t.jsonb :recommended_steps, default: []
      t.text :limitations
      t.boolean :requires_human_review, null: false, default: true
      t.integer :confidence_score, default: 85
      t.string :agent_mode, null: false, default: "simulated_local"
      t.jsonb :raw_response, default: {}
      t.timestamps
    end

    create_table :source_references do |t|
      t.references :investigation, null: false, foreign_key: true
      t.references :knowledge_document, null: false, foreign_key: true
      t.text :quote, null: false
      t.text :relevance_explanation, null: false
      t.integer :chunk_index
      t.timestamps
    end

    create_table :investigation_notes do |t|
      t.references :investigation, null: false, foreign_key: true
      t.references :user, null: false, foreign_key: true
      t.string :note_type, null: false, default: "analyst_comment"
      t.text :body, null: false
      t.timestamps
    end

    create_table :audit_events do |t|
      t.string :trackable_type, null: false
      t.bigint :trackable_id, null: false
      t.references :user, foreign_key: true
      t.string :action, null: false
      t.jsonb :details, default: {}
      t.string :ip_address
      t.datetime :created_at, null: false
    end
    add_index :audit_events, [:trackable_type, :trackable_id]
    add_index :audit_events, :created_at
  end
end
