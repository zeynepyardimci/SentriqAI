class AddInvestigationNoteService
  def initialize(investigation:, user:, note_type:, body:)
    @investigation = investigation.is_a?(Investigation) ? investigation : Investigation.find(investigation)
    @user = user
    @note_type = note_type.to_s
    @body = body.to_s.strip
  end

  def call
    raise ArgumentError, "Note body cannot be empty" if @body.blank?

    note = @investigation.investigation_notes.create!(
      user: @user,
      note_type: @note_type,
      body: @body
    )

    AuditEvent.create!(
      trackable: @investigation,
      user: @user,
      action: "note_added",
      details: {
        note_id: note.id,
        note_type: @note_type
      }
    )

    note
  end
end
