"""Tests for SFT pair extraction and SigmaEval benchmark."""

from __future__ import annotations

from pathlib import Path

import yaml

from training.extract_sft_pairs import extract_pairs
from training.sigma_eval import (
    _detection_coverage,
    _structural_similarity,
    create_benchmark,
    evaluate_benchmark,
    evaluate_pair,
)


# ---------------------------------------------------------------------------
# SFT pair extraction
# ---------------------------------------------------------------------------


class TestExtractPairs:
    def test_extracts_all_rules(self):
        pairs = extract_pairs()
        assert len(pairs) >= 45, f"Expected >=45 pairs, got {len(pairs)}"

    def test_pair_has_required_keys(self):
        pairs = extract_pairs()
        for pair in pairs:
            assert "prompt" in pair
            assert "completion" in pair
            assert "metadata" in pair
            assert "source_file" in pair["metadata"]
            assert "rule_id" in pair["metadata"]

    def test_prompt_contains_threat_info(self):
        pairs = extract_pairs()
        for pair in pairs:
            prompt = pair["prompt"]
            assert "Write a Sigma detection rule" in prompt
            assert "**Threat:**" in prompt
            assert "**Severity:**" in prompt

    def test_completion_is_valid_yaml(self):
        pairs = extract_pairs()
        for pair in pairs:
            data = yaml.safe_load(pair["completion"])
            assert isinstance(data, dict), (
                f"{pair['metadata']['source_file']}: completion is not a dict"
            )
            assert "detection" in data

    def test_prompt_includes_mitre_tactics(self):
        pairs = extract_pairs()
        has_tactics = sum(1 for p in pairs if "MITRE ATT&CK Tactics:" in p["prompt"])
        assert has_tactics > 0, "No pairs include MITRE tactics"

    def test_prompt_includes_false_positives(self):
        pairs = extract_pairs()
        has_fps = sum(1 for p in pairs if "false positives" in p["prompt"].lower())
        assert has_fps > 0, "No pairs include false positives"


# ---------------------------------------------------------------------------
# SigmaEval
# ---------------------------------------------------------------------------

SAMPLE_RULE_A = """\
title: Test Rule A
id: 12345678-1234-1234-1234-123456789abc
status: stable
description: Detects test pattern A.
author: Test
date: "2026-01-01"
references:
  - https://example.com
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection_cmd:
    event_type: tool_call
    command|contains:
      - 'rm -rf'
      - 'sudo rm'
  selection_file:
    event_type: file_write
    file_path|contains: '/etc/passwd'
  condition: selection_cmd or selection_file
falsepositives:
  - Legitimate cleanup scripts
level: critical
"""

SAMPLE_RULE_B = """\
title: Test Rule B
id: 87654321-4321-4321-4321-cba987654321
status: stable
description: Detects test pattern B with different indicators.
author: Test
date: "2026-01-01"
references:
  - https://example.com
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection_cmd:
    event_type: tool_call
    command|contains:
      - 'rm -rf'
      - 'dd if=/dev/zero'
  condition: selection_cmd
falsepositives:
  - Legitimate cleanup scripts
level: high
"""


class TestDetectionCoverage:
    def test_identical_rules_full_coverage(self):
        data = yaml.safe_load(SAMPLE_RULE_A)
        assert _detection_coverage(data, data) == 1.0

    def test_partial_overlap(self):
        gen = yaml.safe_load(SAMPLE_RULE_B)
        ref = yaml.safe_load(SAMPLE_RULE_A)
        coverage = _detection_coverage(gen, ref)
        assert 0.0 < coverage < 1.0, f"Expected partial coverage, got {coverage}"

    def test_empty_detection_zero_coverage(self):
        gen = {"detection": {"condition": "selection"}}
        ref = yaml.safe_load(SAMPLE_RULE_A)
        assert _detection_coverage(gen, ref) == 0.0


class TestStructuralSimilarity:
    def test_identical_rules_perfect(self):
        data = yaml.safe_load(SAMPLE_RULE_A)
        assert _structural_similarity(data, data) == 1.0

    def test_different_level_reduces_score(self):
        ref = yaml.safe_load(SAMPLE_RULE_A)
        gen = yaml.safe_load(SAMPLE_RULE_A)
        gen["level"] = "low"
        sim = _structural_similarity(gen, ref)
        assert sim < 1.0

    def test_different_logsource_reduces_score(self):
        ref = yaml.safe_load(SAMPLE_RULE_A)
        gen = yaml.safe_load(SAMPLE_RULE_A)
        gen["logsource"]["product"] = "windows"
        sim = _structural_similarity(gen, ref)
        assert sim < 1.0


class TestEvaluatePair:
    def test_identical_pair_high_score(self):
        result = evaluate_pair(SAMPLE_RULE_A, SAMPLE_RULE_A)
        assert result["composite_score"] >= 0.90

    def test_different_pair_lower_score(self):
        same = evaluate_pair(SAMPLE_RULE_A, SAMPLE_RULE_A)
        diff = evaluate_pair(SAMPLE_RULE_B, SAMPLE_RULE_A)
        assert diff["composite_score"] < same["composite_score"]

    def test_broken_yaml_low_score(self):
        result = evaluate_pair("[invalid yaml", SAMPLE_RULE_A)
        assert result["composite_score"] < 0.2


class TestEvaluateBenchmark:
    def test_self_eval_perfect_scores(self):
        benchmark = create_benchmark()
        assert len(benchmark) > 0, "Benchmark should have stable rules"
        results = evaluate_benchmark(benchmark, benchmark)
        agg = results["aggregate"]
        assert agg["avg_composite"] >= 0.99, (
            f"Self-eval should be ~1.0, got {agg['avg_composite']}"
        )

    def test_benchmark_only_stable(self):
        benchmark = create_benchmark()
        for item in benchmark:
            assert item["metadata"]["status"] == "stable"
