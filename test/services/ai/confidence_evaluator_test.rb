# frozen_string_literal: true

require "test_helper"

class Ai::ConfidenceEvaluatorTest < ActiveSupport::TestCase
  test "produces deterministic score for identical inputs" do
    context = {
      telemetry: {
        process_name: "vssadmin.exe",
        command_line: "vssadmin delete shadows /all /quiet",
        parent_process: "cmd.exe",
        sha256: "a" * 64,
        network_connection: "192.168.1.50:443"
      },
      missing_fields: []
    }

    res1 = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: 90,
      is_conflicting: false
    )

    res2 = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: 90,
      is_conflicting: false
    )

    assert_equal res1[:score], res2[:score]
    assert_equal res1[:evidence_quality], res2[:evidence_quality]
    assert_equal res1[:calibration_status], "uncalibrated_heuristic"
  end

  test "penalizes evidence quality when critical fields are missing" do
    full_context = {
      telemetry: {
        process_name: "powershell.exe",
        command_line: "powershell -enc JAB...",
        parent_process: "WINWORD.EXE",
        sha256: "e" * 64,
        network_connection: "10.0.0.5:8080"
      },
      missing_fields: []
    }
    sparse_context = {
      telemetry: {
        process_name: "powershell.exe"
      },
      missing_fields: ["command_line", "parent_process", "sha256", "network_connection"]
    }

    full_eval = Ai::ConfidenceEvaluator.evaluate(
      full_context,
      model_confidence: 85,
      is_conflicting: false
    )

    sparse_eval = Ai::ConfidenceEvaluator.evaluate(
      sparse_context,
      model_confidence: 85,
      is_conflicting: false
    )

    assert full_eval[:evidence_quality] > sparse_eval[:evidence_quality],
      "Telemetry with complete telemetry should have higher evidence quality"
    assert full_eval[:score] > sparse_eval[:score],
      "Composite score should penalize sparse evidence despite identical model confidence"
  end

  test "applies penalty when conflicting findings are present" do
    context = {
      telemetry: { process_name: "backup_exec.exe", command_line: "backup_exec.exe /run" },
      missing_fields: []
    }

    clean_eval = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: 75,
      is_conflicting: false
    )

    conflict_eval = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: 75,
      is_conflicting: true
    )

    assert conflict_eval[:score] < clean_eval[:score]
    assert conflict_eval[:evidence_quality] < clean_eval[:evidence_quality]
    assert_includes conflict_eval[:basis], "Çelişkili veya belirsiz"
  end

  test "sanitizes invalid or out-of-range confidence scores" do
    context = {
      telemetry: { process_name: "test.exe" },
      missing_fields: ["command_line"]
    }

    negative_eval = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: -50
    )
    assert_operator negative_eval[:model_confidence], :>=, 10

    overflow_eval = Ai::ConfidenceEvaluator.evaluate(
      context,
      model_confidence: 999
    )
    assert_operator overflow_eval[:model_confidence], :<=, 99
  end

  test "does not produce hardcoded 88 or 95 scores across disparate scenarios" do
    scenarios = [
      {
        model: 92,
        ctx: { telemetry: { process_name: "vssadmin.exe", command_line: "vssadmin delete shadows" }, missing_fields: [] },
        conflict: false
      },
      {
        model: 40,
        ctx: { telemetry: {}, missing_fields: ["process_name", "command_line", "sha256"] },
        conflict: false
      },
      {
        model: 65,
        ctx: { telemetry: { process_name: "svchost.exe" }, missing_fields: ["parent_process"] },
        conflict: true
      }
    ]

    scores = scenarios.map do |s|
      Ai::ConfidenceEvaluator.evaluate(
        s[:ctx],
        model_confidence: s[:model],
        is_conflicting: s[:conflict]
      )[:score]
    end

    # All scores should vary and not fall back to fixed 88 or 95
    assert_equal 3, scores.uniq.size, "Scores should vary dynamically based on context"
    refute_includes scores, 88
    refute_includes scores, 95
  end
end
