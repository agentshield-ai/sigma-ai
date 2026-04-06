"""SigmaEval — evaluation benchmark for Sigma rule generation models.

Scores a model's generated rules against reference rules using the reward
function plus a structural similarity metric. Designed to be run as a
standalone script or imported for programmatic use.

The benchmark consists of (prompt, reference_rule) pairs. For each pair,
the model generates a rule from the prompt, and we score it on:

  1. Reward score (from sigma_reward.py) — syntax, semantics, quality
  2. Detection coverage — do the generated selection blocks cover the
     same threat indicators as the reference?
  3. Structural similarity — field-level overlap between generated and
     reference rules

Usage::

    # Evaluate a JSONL file of generated rules against the benchmark
    python -m training.sigma_eval --generated outputs.jsonl --benchmark benchmark.jsonl

    # Generate the benchmark from existing rules
    python -m training.sigma_eval --create-benchmark -o training/data/sigma_eval_benchmark.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from training.sigma_reward import score_rule


def _extract_detection_indicators(data: dict) -> set[str]:
    """Extract all string values from detection selection blocks.

    Returns the set of indicator strings (field values) that the rule
    is looking for. Used to compare detection coverage between
    generated and reference rules.
    """
    detection = data.get("detection", {})
    if not isinstance(detection, dict):
        return set()

    indicators: set[str] = set()
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field_key, field_val in value.items():
                if isinstance(field_val, str):
                    indicators.add(field_val.lower().strip())
                elif isinstance(field_val, list):
                    for item in field_val:
                        if isinstance(item, str):
                            indicators.add(item.lower().strip())
    return indicators


def _detection_coverage(generated: dict, reference: dict) -> float:
    """Compute detection indicator overlap between generated and reference.

    Returns a score in [0, 1] representing what fraction of the reference
    rule's detection indicators are covered by the generated rule.
    """
    ref_indicators = _extract_detection_indicators(reference)
    if not ref_indicators:
        return 1.0  # nothing to cover

    gen_indicators = _extract_detection_indicators(generated)
    if not gen_indicators:
        return 0.0

    # Exact matches
    exact_matches = ref_indicators & gen_indicators

    # Partial matches (generated indicator contains reference indicator or vice versa)
    partial_matches = set()
    unmatched_ref = ref_indicators - exact_matches
    for ref_ind in unmatched_ref:
        for gen_ind in gen_indicators:
            if ref_ind in gen_ind or gen_ind in ref_ind:
                partial_matches.add(ref_ind)
                break

    covered = len(exact_matches) + 0.5 * len(partial_matches)
    return min(covered / len(ref_indicators), 1.0)


def _structural_similarity(generated: dict, reference: dict) -> float:
    """Compare structural similarity between generated and reference rules.

    Checks: same logsource product/category, same level, overlapping tags,
    similar number of selection blocks.
    """
    score = 0.0
    checks = 0

    # Logsource match
    gen_ls = generated.get("logsource", {})
    ref_ls = reference.get("logsource", {})
    if isinstance(gen_ls, dict) and isinstance(ref_ls, dict):
        checks += 2
        if gen_ls.get("product") == ref_ls.get("product"):
            score += 1.0
        if gen_ls.get("category") == ref_ls.get("category"):
            score += 1.0

    # Level match
    checks += 1
    if generated.get("level") == reference.get("level"):
        score += 1.0

    # Tag overlap
    gen_tags = set(generated.get("tags", []))
    ref_tags = set(reference.get("tags", []))
    if ref_tags:
        checks += 1
        overlap = len(gen_tags & ref_tags) / len(ref_tags)
        score += overlap

    # Selection count similarity
    gen_det = generated.get("detection", {})
    ref_det = reference.get("detection", {})
    if isinstance(gen_det, dict) and isinstance(ref_det, dict):
        gen_sels = len([k for k in gen_det if k != "condition"])
        ref_sels = len([k for k in ref_det if k != "condition"])
        if ref_sels > 0:
            checks += 1
            ratio = min(gen_sels, ref_sels) / max(gen_sels, ref_sels)
            score += ratio

    return score / checks if checks > 0 else 0.0


def evaluate_pair(
    generated_yaml: str,
    reference_yaml: str,
    prompt: str = "",
) -> dict[str, Any]:
    """Evaluate a single generated rule against a reference.

    Returns a dict with individual scores and a composite score.
    """
    reward = score_rule(generated_yaml, prompt)

    try:
        gen_data = yaml.safe_load(generated_yaml)
    except yaml.YAMLError:
        gen_data = None

    try:
        ref_data = yaml.safe_load(reference_yaml)
    except yaml.YAMLError:
        ref_data = None

    if not isinstance(gen_data, dict) or not isinstance(ref_data, dict):
        return {
            "reward_score": reward,
            "detection_coverage": 0.0,
            "structural_similarity": 0.0,
            "composite_score": reward * 0.4,
        }

    coverage = _detection_coverage(gen_data, ref_data)
    similarity = _structural_similarity(gen_data, ref_data)

    # Weighted composite: 40% reward, 35% detection coverage, 25% structural
    composite = 0.40 * reward + 0.35 * coverage + 0.25 * similarity

    return {
        "reward_score": round(reward, 4),
        "detection_coverage": round(coverage, 4),
        "structural_similarity": round(similarity, 4),
        "composite_score": round(composite, 4),
    }


def evaluate_benchmark(
    generated: list[dict],
    benchmark: list[dict],
) -> dict[str, Any]:
    """Evaluate a full benchmark set.

    Parameters
    ----------
    generated:
        List of dicts with "prompt" and "completion" keys.
    benchmark:
        List of dicts with "prompt" and "completion" keys (reference rules).

    Returns
    -------
    dict with per-example results and aggregate statistics.
    """
    results = []
    for gen, ref in zip(generated, benchmark):
        result = evaluate_pair(
            gen["completion"],
            ref["completion"],
            ref["prompt"],
        )
        result["prompt"] = ref["prompt"][:100] + "..."
        result["reference_title"] = ref.get("metadata", {}).get("title", "")
        results.append(result)

    if not results:
        return {"results": [], "aggregate": {}}

    avg = lambda key: sum(r[key] for r in results) / len(results)

    return {
        "results": results,
        "aggregate": {
            "n": len(results),
            "avg_reward": round(avg("reward_score"), 4),
            "avg_coverage": round(avg("detection_coverage"), 4),
            "avg_similarity": round(avg("structural_similarity"), 4),
            "avg_composite": round(avg("composite_score"), 4),
        },
    }


def create_benchmark(rules_dir: Path | None = None) -> list[dict]:
    """Create a benchmark set from existing rules.

    Uses the SFT pair extractor to generate (prompt, reference) pairs,
    then splits: stable rules become the benchmark, non-stable are
    excluded (they may have quality issues).
    """
    from training.extract_sft_pairs import extract_pairs

    pairs = extract_pairs(rules_dir)
    # Only include stable rules in the benchmark
    benchmark = [p for p in pairs if p["metadata"].get("status") == "stable"]
    return benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="SigmaEval benchmark")
    parser.add_argument(
        "--create-benchmark",
        action="store_true",
        help="Create benchmark from existing stable rules",
    )
    parser.add_argument(
        "--generated",
        type=str,
        help="JSONL file with generated rules to evaluate",
    )
    parser.add_argument(
        "--benchmark",
        type=str,
        help="JSONL file with benchmark (reference) rules",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file (default: stdout)",
    )
    args = parser.parse_args()

    if args.create_benchmark:
        benchmark = create_benchmark()
        out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
        try:
            for item in benchmark:
                out.write(json.dumps(item, ensure_ascii=False) + "\n")
        finally:
            if out is not sys.stdout:
                out.close()
        if args.output:
            print(
                f"Wrote {len(benchmark)} benchmark pairs to {args.output}",
                file=sys.stderr,
            )
        return

    if args.generated and args.benchmark:
        with open(args.generated, encoding="utf-8") as f:
            generated = [json.loads(line) for line in f if line.strip()]
        with open(args.benchmark, encoding="utf-8") as f:
            benchmark = [json.loads(line) for line in f if line.strip()]

        results = evaluate_benchmark(generated, benchmark)

        out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
        try:
            json.dump(results, out, indent=2, ensure_ascii=False)
            out.write("\n")
        finally:
            if out is not sys.stdout:
                out.close()

        agg = results["aggregate"]
        print(
            f"\nSigmaEval Results (n={agg['n']}):\n"
            f"  Reward:     {agg['avg_reward']:.4f}\n"
            f"  Coverage:   {agg['avg_coverage']:.4f}\n"
            f"  Similarity: {agg['avg_similarity']:.4f}\n"
            f"  Composite:  {agg['avg_composite']:.4f}",
            file=sys.stderr,
        )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
