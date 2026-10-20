class CreateTicketsAndTicketNotes < ActiveRecord::Migration[8.1]
  def change
    create_table :tickets do |t|
      t.string :ticket_number, null: false
      t.string :title, null: false
      t.text :description, null: false
      t.string :status, null: false, default: "open"
      t.string :priority, null: false, default: "medium"
      t.string :assigned_agent
      t.string :idempotency_key
      t.references :detection, foreign_key: true
      t.references :user, foreign_key: true
      t.references :human_reviewer, foreign_key: { to_table: :users }
      t.jsonb :context_metadata, default: {}
      t.jsonb :llm_analysis, default: {}
      t.string :human_decision
      t.text :human_decision_notes
      t.datetime :human_reviewed_at
      t.string :agent_mode, null: false, default: "simulated_local"
      t.timestamps
    end
    add_index :tickets, :ticket_number, unique: true
    add_index :tickets, :idempotency_key, unique: true
    add_index :tickets, :status
    add_index :tickets, :priority

    create_table :ticket_notes do |t|
      t.references :ticket, null: false, foreign_key: true
      t.references :user, foreign_key: true
      t.string :author_type, null: false, default: "agent"
      t.string :author_name, null: false, default: "External Agent"
      t.string :note_type, null: false, default: "finding"
      t.text :body, null: false
      t.jsonb :metadata, default: {}
      t.timestamps
    end
    add_index :ticket_notes, [:ticket_id, :created_at]
  end
end
