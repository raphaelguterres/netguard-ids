# NetGuard XDR Detection Engine

## Objective
Build a lightweight, explainable, SaaS-ready detection layer for endpoint telemetry using:

- modular rules
- deterministic behavior
- lightweight host baselines
- optional ML enrichment
- clean separation from correlation and response

## Runtime Flow
```text
Endpoint event
  -> schema normalization
  -> host state update
  -> baseline assessment
  -> rule evaluation
  -> detection records
  -> correlation engine
  -> response planning
  -> risk scoring
```

## Detection Module Architecture
Current implementation:

- `xdr/detection.py`
  - orchestrates host state, baseline adapter, rules, and dedupe
- `xdr/detections/base.py`
  - rule contract, context object, helper builders
- `xdr/detections/state.py`
  - host behavior profile, temporal counters, lightweight baseline logic, optional `MLBaseline` bridge
- `xdr/detections/process_rules.py`
  - interpreter abuse, encoded commands, rare process, suspicious process tree
- `xdr/detections/auth_rules.py`
  - brute force, failure-then-success, unusual login hour
- `xdr/detections/persistence_rules.py`
  - startup entries, scheduled task, service, registry persistence
- `xdr/detections/network_rules.py`
  - unusual outbound port, rare destination, basic beaconing

## Rule Structure Pattern
Every rule follows the same shape:

1. declare `rule_id`, `rule_name`, `supported_event_types`
2. evaluate a `DetectionContext`
3. emit one or more `DetectionRecord`
4. attach tags, confidence, description, related events, and recommended action

Example pattern:
```python
class ExampleRule(DetectionRule):
    rule_id = "NG-EDR-999"
    rule_name = "Example behavior"
    supported_event_types = ("process_execution",)

    def evaluate(self, context: DetectionContext):
        if not suspicious_condition:
            return []
        return [
            self.detection(
                severity="medium",
                confidence=0.76,
                description="Explainable behavior trigger.",
                context=context,
                tags=["example", "behavior"],
                details={"why": "matched threshold"},
            )
        ]
```

## Implemented Example Rules
- `NG-EDR-001` Suspicious PowerShell execution
- `NG-EDR-002` Suspicious Bash execution
- `NG-EDR-003` Brute force authentication pattern
- `NG-EDR-004` Persistence mechanism observed
- `NG-EDR-005` Suspicious process tree
- `NG-EDR-006` Unusual outbound connection
- `NG-EDR-007` Rare process on host baseline
- `NG-EDR-008` Encoded command execution
- `NG-EDR-009` Repeated failures followed by success
- `NG-EDR-010` Login outside normal time window
- `NG-EDR-011` Rare outbound destination
- `NG-EDR-012` Repeated outbound beaconing pattern
- `NG-EDR-013` ML baseline behavior deviation
- `NG-EDR-014` Unusual parent-child relationship

## Severity Scoring Approach
Detection severity stays deterministic and explainable:

- `low`
  - weak anomaly, low confidence, baseline-only deviation
- `medium`
  - single suspicious signal with limited blast radius
- `high`
  - strong suspicious behavior or repeated abuse pattern
- `critical`
  - execution + evasion + persistence or correlation-confirmed incident

Practical scoring model:

- single baseline anomaly -> `medium`
- repeated failures or rare outbound pattern -> `medium/high`
- malicious interpreter behavior -> `high`
- beaconing + script abuse or execution + persistence -> `critical`

Pipeline host risk uses weighted severity accumulation:

- `low` = 5
- `medium` = 15
- `high` = 35
- `critical` = 60

## ML Baseline Integration
The detection engine does not depend on ML to work.

ML is additive:

- `BehavioralBaselineAdapter` keeps lightweight statistical baselines per host
- if `engine.ml_baseline.MLBaseline` is available, it receives synthetic host snapshots from the rolling event stream
- ML output becomes an explainable detection signal `NG-EDR-013`
- if scikit-learn is absent, the engine still works normally

This keeps the platform production-friendly and easy to deploy.

## Correlation Integration
Correlation is intentionally decoupled from rule IDs where possible.

Current integration uses detection tags such as:

- `script_abuse`
- `persistence`
- `auth_abuse`
- `beaconing`

This allows:

- detection rules to evolve without constantly rewriting the correlation engine
- weak signals to be combined into higher-confidence incidents

Examples:

- repeated suspicious script executions -> `NG-XDR-COR-001`
- suspicious script + persistence -> `NG-XDR-COR-002`
- auth abuse + execution -> `NG-XDR-COR-003`
- beaconing + execution -> `NG-XDR-COR-004`

## Response Integration
Response logic consumes tags instead of fragile hard-coded rule lists.

Examples:

- `script_abuse` or dangerous `process_tree` -> `kill_process`
- `script_abuse` or `encoded_command` -> `block_execution_pattern`
- `auth_abuse` -> `block_source_ip`
- high/critical overall severity -> incident ticket + host risk tagging

## Detection Output Schema
Each detection record now contains:

- `rule_id`
- `rule_name`
- `severity`
- `confidence`
- `summary`
- `tags`
- `details`
- `related_events`
- `recommended_action`

This makes detections fit both SOC workflows and future endpoint response actions.

## Suggested Folder Structure
Recommended long-term structure:

```text
xdr/
  detection.py
  correlation.py
  response.py
  pipeline.py
  schema.py
  severity.py
  detections/
    base.py
    state.py
    process_rules.py
    auth_rules.py
    persistence_rules.py
    network_rules.py
```

If the product grows, the next split is:

```text
xdr/detections/
  process/
  auth/
  persistence/
  network/
  cloud/
```

## Naming Convention
Current stable convention:

- `NG-EDR-###` for detections
- `NG-XDR-COR-###` for correlations

Practical rule naming:

- concise action-oriented name
- behavior-focused, not malware-family focused
- examples:
  - `Suspicious PowerShell execution`
  - `Repeated failures followed by success`
  - `Rare outbound destination`

## Why This Design Works
- easy to read
- easy to extend
- low dependency footprint
- deterministic for analysts
- compatible with multi-tenant SaaS operation
- strong enough for SMB EDR/XDR use cases without overengineering
