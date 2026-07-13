"""Tests for the ATR -> agent_events processing pipeline.

The pipeline (pipelines/atr-agent-events.yml) translates Sigma rules
exported by ATR's generate-sigma.py (logsource category
ai_agent_content, ATR surface field names) into the agent_events
taxonomy used by this ruleset. Fixture rules below are reduced
versions of ATR exports (MIT licensed,
https://github.com/Agent-Threat-Rule/agent-threat-rules).
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

sigma = pytest.importorskip("sigma")

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingPipeline

PIPELINE_PATH = (
    Path(__file__).resolve().parent.parent / "pipelines" / "atr-agent-events.yml"
)


@pytest.fixture(scope="module")
def pipeline() -> ProcessingPipeline:
    return ProcessingPipeline.from_yaml(PIPELINE_PATH.read_text())


def _apply(pipeline: ProcessingPipeline, rule_yaml: str):
    rule = SigmaCollection.from_yaml(rule_yaml).rules[0]
    copy.deepcopy(pipeline).apply(rule)
    return rule


def _fields(rule) -> set[str]:
    found: set[str] = set()

    def walk(obj) -> None:
        field = getattr(obj, "field", None)
        if field:
            found.add(field)
        for child in getattr(obj, "detection_items", []) or []:
            walk(child)

    for detection in rule.detection.detections.values():
        walk(detection)
    return found


def _rule(surface_line: str, condition: str = "a") -> str:
    return f"""
title: fixture
id: 44444444-4444-4444-4444-444444444444
status: experimental
logsource:
    product: ai_agent
    category: ai_agent_content
detection:
    a:
        {surface_line}
    condition: {condition}
"""


def test_pipeline_loads(pipeline: ProcessingPipeline) -> None:
    assert pipeline.items, "pipeline has no processing items"


@pytest.mark.parametrize(
    ("surface_line", "expected_field", "expected_event_type"),
    [
        ("user_input|contains: 'ignore previous'", "content", "user_input"),
        ("tool_response|contains: 'BEGIN PRIVATE KEY'", "content", "tool_response"),
        ("agent_output|contains: 'curl http'", "content", "output_generation"),
        ("tool_description|contains: '<IMPORTANT>'", "content", "tool_description"),
        ("tool_args|contains: '169.254.169.254'", "arguments", "tool_call"),
        ("tool_name|contains: 'shadow'", "tool_name", "tool_call"),
    ],
)
def test_surface_mapping(
    pipeline: ProcessingPipeline,
    surface_line: str,
    expected_field: str,
    expected_event_type: str,
) -> None:
    rule = _apply(pipeline, _rule(surface_line))
    assert rule.logsource.category == "agent_events"
    assert expected_field in _fields(rule)
    event_sel = rule.detection.detections.get("atr_event_type")
    assert event_sel is not None, "event_type selection was not injected"
    plain = event_sel.to_plain()
    assert plain == {"event_type": expected_event_type}
    condition = rule.detection.parsed_condition[0].condition
    assert condition.startswith("atr_event_type and ("), condition


def test_mixed_surfaces_are_refused(pipeline: ProcessingPipeline) -> None:
    mixed = """
title: mixed fixture
id: 55555555-5555-5555-5555-555555555555
status: experimental
logsource:
    product: ai_agent
    category: ai_agent_content
detection:
    a:
        user_input|contains: 'x'
    b:
        tool_description|contains: 'y'
    condition: a and b
"""
    with pytest.raises(SigmaTransformationError):
        _apply(pipeline, mixed)


def test_bare_content_gets_no_event_type(pipeline: ProcessingPipeline) -> None:
    rule = _apply(pipeline, _rule("content|contains: 'x'"))
    assert rule.logsource.category == "agent_events"
    assert "atr_event_type" not in rule.detection.detections
    assert rule.detection.parsed_condition[0].condition == "a"


def test_native_rules_pass_through(pipeline: ProcessingPipeline) -> None:
    native = """
title: native fixture
id: 66666666-6666-6666-6666-666666666666
status: experimental
logsource:
    product: ai_agent
    category: agent_events
detection:
    a:
        event_type: tool_call
        command|contains: 'rm -rf'
    condition: a
"""
    rule = _apply(pipeline, native)
    assert rule.logsource.category == "agent_events"
    assert list(rule.detection.detections) == ["a"]
    assert rule.detection.parsed_condition[0].condition == "a"

