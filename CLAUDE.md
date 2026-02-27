# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AgentShield Sigma Rules — a library of 45 Sigma detection rules for identifying adversarial attacks against AI agents (prompt injection, data theft, tool poisoning, privilege escalation, RCE, persistence, etc.). Rules follow the [Sigma open standard](https://sigmahq.io/) and are vendor-neutral.

## Commands

```bash
# Run all conformance tests
pytest tests/test_sigma_conformance.py -v

# Run a single test
pytest tests/test_sigma_conformance.py::test_all_rules_pass_sigma_check -v

# Lint all rules with sigma-cli (strict mode — errors AND issues)
sigma check -e -i rules/

# If sigma-cli is not installed globally, use a venv:
python3 -m venv /tmp/sigma-venv
/tmp/sigma-venv/bin/pip install sigma-cli pySigma
/tmp/sigma-venv/bin/sigma check -e -i rules/
```

**Dependencies for testing:** PyYAML, pytest, sigma-cli, pySigma.

## Architecture

This is a **rule data repository**, not a Python package — there is no `pyproject.toml` or build system.

### Rule files (`rules/ai_agent/*.yml`)

All 45 rules live in a single flat directory following SigmaHQ conventions. Each YAML file is a self-contained Sigma rule with: `title`, `id` (UUID), `status` (stable/test/experimental), `description`, `author`, `date`, `tags` (MITRE ATT&CK), `logsource` (product: `ai_agent`, category: `agent_events`), `detection` (selection blocks + condition), `falsepositives`, `level`.

**Custom AgentShield extensions** (used in test/experimental rules): temporal correlation (`time_window`, `time_between`), behavioural analysis (`cross_plugin_data_flow`, `suspicious_data_pattern`), content analysis (`description_similarity_score`, `byte_size_to_visible_char_ratio`), network analysis (`query_length`, `subdomain_count`, `domain_entropy`).

### Test suite (`tests/`)

Six pytest-based conformance tests validate all rules:

1. **sigma check** — strict lint via `sigma check -e -i` (skipped if sigma-cli not installed)
2. **required fields** — stable rules must have all mandatory Sigma fields
3. **references** — stable rules must cite at least one reference
4. **condition cross-reference** — every identifier in `condition` must exist as a `detection` key (handles wildcards like `selection_*`)
5. **unique IDs** — no duplicate UUIDs across rules
6. **tactic tag format** — MITRE ATT&CK tactic tags use hyphens not underscores

Fixtures are session-scoped in `conftest.py` for efficiency. The `stable_rules` fixture filters to `status: stable` rules only.

## Rule Conventions

- File naming: `ai_agent_<threat_category>.yml`
- Rule IDs: UUID v5, globally unique
- Tags: `attack.<tactic>` (hyphenated, e.g. `attack.initial-access`) and `attack.t<number>` for techniques
- Maturity progression: experimental → test → stable (stable requires all fields + references)
- Logsource: always `product: ai_agent`, `category: agent_events`
- OpenClaw-specific rules use `product: openclaw` with `service: agent_events`
