require "test_helper"

class InvestigationSchemaValidatorTest < ActiveSupport::TestCase
  test "valid payload passes validation" do
    payload = {
      summary: "Executive analysis of incident",
      observed_evidence: ["PowerShell executed with -Enc flag"],
      possible_causes: [{ hypothesis: "T1059.001", likelihood: "High", rationale: "Known flag" }],
      evidence_gaps: ["Missing network pcap"],
      recommended_steps: ["Isolate host"],
      requires_human_review: true,
      confidence_score: 85
    }

    result = InvestigationSchemaValidator.validate(payload)
    assert_equal "Executive analysis of incident", result["summary"]
    assert_equal true, result["requires_human_review"]
  end

  test "missing required key raises ValidationError" do
    payload = {
      summary: "Executive analysis",
      observed_evidence: []
      # Missing possible_causes, evidence_gaps, recommended_steps, requires_human_review
    }

    assert_raises(InvestigationSchemaValidator::ValidationError) do
      InvestigationSchemaValidator.validate(payload)
    end
  end

  test "malformed JSON string raises ValidationError instead of crashing" do
    assert_raises(InvestigationSchemaValidator::ValidationError) do
      InvestigationSchemaValidator.validate("{ malformed json: not valid ")
    end
  end
end
