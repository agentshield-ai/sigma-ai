"""Extract SFT training pairs from existing Sigma rules.

Reads every rule in rules/ai_agent/ and produces (prompt, completion) pairs
in JSONL format suitable for supervised fine-tuning.

The prompt is a natural-language threat description synthesised from the
rule's metadata. The completion is the full Sigma YAML.

Usage::

    python -m training.extract_sft_pairs              # writes to stdout
    python -m training.extract_sft_pairs -o data.jsonl # writes to file
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "ai_agent"

# MITRE ATT&CK tactic display names
_TACTIC_DISPLAY = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "command-and-control": "Command and Control",
    "resource-development": "Resource Development",
    "reconnaissance": "Reconnaissance",
    "impact": "Impact",
}


def _extract_tactics(tags: list[str]) -> list[str]:
    """Extract human-readable tactic names from MITRE tags."""
    tactics = []
    for tag in tags:
        if tag.startswith("attack.") and not tag.startswith("attack.t"):
            tactic_key = tag[len("attack."):]
            display = _TACTIC_DISPLAY.get(tactic_key)
            if display:
                tactics.append(display)
    return tactics


def _extract_techniques(tags: list[str]) -> list[str]:
    """Extract technique IDs from MITRE tags."""
    return [
        tag[len("attack."):].upper()
        for tag in tags
        if tag.startswith("attack.t")
    ]


def _build_prompt(data: dict) -> str:
    """Synthesise a natural-language prompt from rule metadata."""
    title = data.get("title", "Unknown Threat")
    description = data.get("description", "").strip()
    level = data.get("level", "medium")
    tags = data.get("tags", [])
    tactics = _extract_tactics(tags)
    techniques = _extract_techniques(tags)
    falsepositives = data.get("falsepositives", [])

    # Determine product context
    logsource = data.get("logsource", {})
    product = logsource.get("product", "ai_agent")
    if product == "openclaw":
        context = "an OpenClaw AI agent"
    else:
        context = "an AI agent"

    lines = [
        f"Write a Sigma detection rule for the following threat against {context}:",
        "",
        f"**Threat:** {title}",
        "",
    ]

    if description:
        lines.append(f"**Description:** {description}")
        lines.append("")

    if tactics:
        lines.append(f"**MITRE ATT&CK Tactics:** {', '.join(tactics)}")
    if techniques:
        lines.append(f"**MITRE ATT&CK Techniques:** {', '.join(techniques)}")
    if level:
        lines.append(f"**Severity:** {level}")

    if falsepositives:
        lines.append("")
        lines.append("**Known false positives to consider:**")
        for fp in falsepositives:
            lines.append(f"- {fp}")

    lines.append("")
    lines.append(
        "Generate a complete Sigma rule in YAML format with appropriate "
        "detection logic, including selection blocks and condition."
    )

    return "\n".join(lines)


def extract_pairs(rules_dir: Path | None = None) -> list[dict]:
    """Extract (prompt, completion) pairs from all rules.

    Returns a list of dicts with keys: prompt, completion, metadata.
    """
    if rules_dir is None:
        rules_dir = RULES_DIR

    pairs = []
    for path in sorted(rules_dir.glob("*.yml")):
        raw = path.read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue

        if not isinstance(data, dict):
            continue

        prompt = _build_prompt(data)
        pairs.append({
            "prompt": prompt,
            "completion": raw,
            "metadata": {
                "source_file": path.name,
                "rule_id": data.get("id", ""),
                "status": data.get("status", ""),
                "title": data.get("title", ""),
                "level": data.get("level", ""),
            },
        })

    return pairs


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract SFT training pairs")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "--rules-dir",
        type=str,
        default=None,
        help=f"Rules directory (default: {RULES_DIR})",
    )
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir) if args.rules_dir else RULES_DIR
    pairs = extract_pairs(rules_dir)

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        for pair in pairs:
            out.write(json.dumps(pair, ensure_ascii=False) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    if args.output:
        print(f"Wrote {len(pairs)} training pairs to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
