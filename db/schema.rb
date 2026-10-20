# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_10_21_000002) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"
  enable_extension "vector"

  create_table "audit_events", force: :cascade do |t|
    t.string "trackable_type", null: false
    t.bigint "trackable_id", null: false
    t.bigint "user_id"
    t.string "action", null: false
    t.jsonb "details", default: {}
    t.string "ip_address"
    t.datetime "created_at", null: false
    t.index ["created_at"], name: "index_audit_events_on_created_at"
    t.index ["trackable_type", "trackable_id"], name: "index_audit_events_on_trackable_type_and_trackable_id"
    t.index ["user_id"], name: "index_audit_events_on_user_id"
  end

  create_table "detections", force: :cascade do |t|
    t.string "title", null: false
    t.text "description"
    t.string "severity", default: "medium", null: false
    t.string "status", default: "new", null: false
    t.string "hostname", null: false
    t.string "ip_address"
    t.string "username"
    t.string "process_name"
    t.integer "process_id"
    t.string "parent_process_name"
    t.integer "parent_process_id"
    t.text "command_line"
    t.string "file_path"
    t.string "file_hash"
    t.datetime "triggered_at", null: false
    t.boolean "sla_risk", default: false, null: false
    t.datetime "sla_breached_at"
    t.bigint "assigned_to_id"
    t.jsonb "raw_telemetry", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["assigned_to_id"], name: "index_detections_on_assigned_to_id"
    t.index ["severity"], name: "index_detections_on_severity"
    t.index ["sla_risk"], name: "index_detections_on_sla_risk"
    t.index ["status"], name: "index_detections_on_status"
    t.index ["triggered_at"], name: "index_detections_on_triggered_at"
  end

  create_table "evidences", force: :cascade do |t|
    t.bigint "detection_id", null: false
    t.string "evidence_type", null: false
    t.datetime "occurred_at", null: false
    t.text "description", null: false
    t.jsonb "details", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["detection_id", "occurred_at"], name: "index_evidences_on_detection_id_and_occurred_at"
    t.index ["detection_id"], name: "index_evidences_on_detection_id"
  end

  create_table "investigation_notes", force: :cascade do |t|
    t.bigint "investigation_id", null: false
    t.bigint "user_id", null: false
    t.string "note_type", default: "analyst_comment", null: false
    t.text "body", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["investigation_id"], name: "index_investigation_notes_on_investigation_id"
    t.index ["user_id"], name: "index_investigation_notes_on_user_id"
  end

  create_table "investigations", force: :cascade do |t|
    t.bigint "detection_id", null: false
    t.bigint "user_id", null: false
    t.string "status", default: "completed", null: false
    t.text "summary", null: false
    t.jsonb "observed_evidence", default: []
    t.jsonb "possible_causes", default: []
    t.jsonb "evidence_gaps", default: []
    t.jsonb "recommended_steps", default: []
    t.text "limitations"
    t.boolean "requires_human_review", default: true, null: false
    t.integer "confidence_score", default: 85
    t.string "agent_mode", default: "simulated_local", null: false
    t.jsonb "raw_response", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["detection_id"], name: "index_investigations_on_detection_id"
    t.index ["user_id"], name: "index_investigations_on_user_id"
  end

  create_table "knowledge_chunks", force: :cascade do |t|
    t.bigint "knowledge_document_id", null: false
    t.integer "chunk_index", null: false
    t.text "chunk_text", null: false
    t.string "keywords"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["knowledge_document_id", "chunk_index"], name: "idx_on_knowledge_document_id_chunk_index_7fbbe56dc3", unique: true
    t.index ["knowledge_document_id"], name: "index_knowledge_chunks_on_knowledge_document_id"
  end

  create_table "knowledge_documents", force: :cascade do |t|
    t.string "title", null: false
    t.string "category", null: false
    t.string "external_reference"
    t.text "content", null: false
    t.jsonb "metadata", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["category"], name: "index_knowledge_documents_on_category"
  end

  create_table "source_references", force: :cascade do |t|
    t.bigint "investigation_id", null: false
    t.bigint "knowledge_document_id", null: false
    t.text "quote", null: false
    t.text "relevance_explanation", null: false
    t.integer "chunk_index"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["investigation_id"], name: "index_source_references_on_investigation_id"
    t.index ["knowledge_document_id"], name: "index_source_references_on_knowledge_document_id"
  end

  create_table "ticket_notes", force: :cascade do |t|
    t.bigint "ticket_id", null: false
    t.bigint "user_id"
    t.string "author_type", default: "agent", null: false
    t.string "author_name", default: "External Agent", null: false
    t.string "note_type", default: "finding", null: false
    t.text "body", null: false
    t.jsonb "metadata", default: {}
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["ticket_id", "created_at"], name: "index_ticket_notes_on_ticket_id_and_created_at"
    t.index ["ticket_id"], name: "index_ticket_notes_on_ticket_id"
    t.index ["user_id"], name: "index_ticket_notes_on_user_id"
  end

  create_table "tickets", force: :cascade do |t|
    t.string "ticket_number", null: false
    t.string "title", null: false
    t.text "description", null: false
    t.string "status", default: "open", null: false
    t.string "priority", default: "medium", null: false
    t.string "assigned_agent"
    t.string "idempotency_key"
    t.bigint "detection_id"
    t.bigint "user_id"
    t.bigint "human_reviewer_id"
    t.jsonb "context_metadata", default: {}
    t.jsonb "llm_analysis", default: {}
    t.string "human_decision"
    t.text "human_decision_notes"
    t.datetime "human_reviewed_at"
    t.string "agent_mode", default: "simulated_local", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["detection_id"], name: "index_tickets_on_detection_id"
    t.index ["human_reviewer_id"], name: "index_tickets_on_human_reviewer_id"
    t.index ["idempotency_key"], name: "index_tickets_on_idempotency_key", unique: true
    t.index ["priority"], name: "index_tickets_on_priority"
    t.index ["status"], name: "index_tickets_on_status"
    t.index ["ticket_number"], name: "index_tickets_on_ticket_number", unique: true
    t.index ["user_id"], name: "index_tickets_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "email", null: false
    t.string "name", null: false
    t.string "role", default: "analyst", null: false
    t.string "demo_token", null: false
    t.string "password_digest"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["demo_token"], name: "index_users_on_demo_token", unique: true
    t.index ["email"], name: "index_users_on_email", unique: true
  end

  add_foreign_key "audit_events", "users"
  add_foreign_key "detections", "users", column: "assigned_to_id"
  add_foreign_key "evidences", "detections"
  add_foreign_key "investigation_notes", "investigations"
  add_foreign_key "investigation_notes", "users"
  add_foreign_key "investigations", "detections"
  add_foreign_key "investigations", "users"
  add_foreign_key "knowledge_chunks", "knowledge_documents"
  add_foreign_key "source_references", "investigations"
  add_foreign_key "source_references", "knowledge_documents"
  add_foreign_key "ticket_notes", "tickets"
  add_foreign_key "ticket_notes", "users"
  add_foreign_key "tickets", "detections"
  add_foreign_key "tickets", "users"
  add_foreign_key "tickets", "users", column: "human_reviewer_id"
end
