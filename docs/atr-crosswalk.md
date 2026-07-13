# ATR crosswalk

[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) (ATR) is an MIT-licensed ruleset covering a near-identical threat taxonomy to sigma-ai at a different enforcement point: ATR scans agent artefacts statically (MCP manifests, skills, supply chain), whereas sigma-ai detects at runtime over agent telemetry.

A crosswalk mapping ATR categories and rules to sigma-ai through shared MITRE ATT&CK technique identifiers is maintained in the ATR repository and regenerated from rule metadata under CI, so it does not go stale: [atr-attack-crosswalk.md](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/crosswalks/atr-attack-crosswalk.md).

The join convention is the enterprise ATT&CK technique identifier. Our rules carry `tags: attack.t1059`; ATR rules carry `references.mitre_attack: T1059`. The two align after case folding. The crosswalk additionally surfaces MITRE ATLAS and OWASP Agentic mappings, which ATR carries as machine-readable metadata and we do not tag.

ATR also ships a YAML to Sigma converter whose output passes our structural conformance checks. Its exports use ATR surface field names (`user_input`, `tool_response`, `tool_args` and so on) against `logsource.category: ai_agent_content`; the processing pipeline in `pipelines/atr-agent-events.yml` translates these into our `agent_events` taxonomy for use with the agentshield engine. See [issue #9](https://github.com/agentshield-ai/sigma-ai/issues/9) for the discussion.
