# frozen_string_literal: true

class CreateCopilotMessages < ActiveRecord::Migration[8.1]
  def change
    create_table :copilot_messages do |t|
      t.references :detection, foreign_key: true, null: true
      t.references :ticket, foreign_key: true, null: true
      t.references :user, foreign_key: true, null: true
      t.string :role, null: false # 'user', 'avatar', 'system'
      t.text :content, null: false
      t.string :intent
      t.boolean :audio_spoken, default: false
      t.string :action_taken
      t.jsonb :metadata, default: {}

      t.timestamps
    end

    add_index :copilot_messages, [:detection_id, :created_at]
    add_index :copilot_messages, [:ticket_id, :created_at]
  end
end
