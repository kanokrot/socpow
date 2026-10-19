# Flow B/C Operational Metrics - 2026-09-27

## What this measures

This report measures operational behavior for two investigation flows:

- **Flow B**: `agent_loop.py` sessions where `playbook_id IS NULL`.
- **Flow C**: `playbook_engine.py` sessions where `playbook_id IS NOT NULL`.

The report defines three operational metrics in `compute_operational_metrics.py`:

- `step_success_rate`: successful recorded tool steps divided by recorded tool steps. Flow B uses successful `audit_log` tool-call rows; Flow C uses `agent_steps` tool-call rows whose JSON result does not contain an `error` key.
- `completion_rate`: sessions with `status='completed'` divided by sessions in the flow.
- `human_override_rate`: rejected approval decisions divided by completed approval decisions. A zero denominator is emitted as `0.000000` by the script, but it is not evidence that the measured rate is 0%.

The CSV also includes completion-rate breakdown rows for step-limit aborts and other non-completed sessions.

## Snapshot scope and reruns

The table below is the archived 2026-09-27 snapshot: Flow B has 15 sessions and Flow C has 4 sessions. It is not a current all-session result. The script's default query selects every session currently in the database; running it later can include sessions created after this snapshot and will not reproduce these counts. The archived `operational_metrics_output.csv` is the source for the values in this section.

The script accepts `--since`, which is a lower time bound only; it has no end-time or explicit session-ID filter. Use the 2026-10-13 report for the later, explicitly selected Flow C cohorts. Do not use the Flow B rows in that report as a rerun of the 15-session Flow B cohort: those selected session lists contain Flow C sessions only.

## How to run against the current database

From the repository root, run the copied script against the live database:

```powershell
python evidence/operational_metrics_2026-09-27/compute_operational_metrics.py --db-path "C:\Users\ACER\.blue-team-assistant\cache\agent.db"
```

The database is opened read-only. The CSV is written beside the script as `operational_metrics_output.csv`. This command reports the current database contents and does not reproduce the archived snapshot above.

## Raw results

| group | metric | numerator | denominator | rate |
|---|---|---:|---:|---:|
| Flow B | step_success_rate | 85 | 86 | 0.988372 |
| Flow B | completion_rate | 14 | 15 | 0.933333 |
| Flow B | completion_rate_step_limit_abort_breakdown | 0 | 1 | 0.000000 |
| Flow B | completion_rate_other_non_completed_breakdown | 1 | 1 | 1.000000 |
| Flow B | human_override_rate | 0 | 0 | 0.000000 |
| Flow C | step_success_rate | 15 | 20 | 0.750000 |
| Flow C | completion_rate | 4 | 4 | 1.000000 |
| Flow C | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
| Flow C | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
| Flow C | human_override_rate | 0 | 5 | 0.000000 |

## Sample sizes and caveats

- Flow B: **n=15 sessions** (test goals fired via `scripts/adhoc/generate_flow_b_sessions.py`). Flow C: **n=4 sessions** (organic, from prior testing). Both are small samples, not production-scale.
- Flow B `human_override_rate` is **0/0**. The script counts only completed audit decisions with `requires_approval=1` and `action_type` equal to `approval_granted` or `approval_rejected`; it excludes pending `approval_required` events. A zero denominator is printed as `0.000000`, but it is not a 0% measured rate. The separate read-only audit-log query below found no approval events in the 15 Flow B sessions, which supports the statement that no approval gate was triggered in that cohort. Do not infer that statement from the metric row alone.
- Flow C `human_override_rate` is **0/5=0%**: 5 real approval gates were hit, all were granted, and none were rejected. This is a real measured rate but based on a small sample.
- Flow B `completion_rate` (**14/15**) is a conservative lower bound: one `failed` session (`3ff001cbb6c7`) actually produced a correct, complete `MALICIOUS` verdict (threat score 80, AbuseIPDB 22 reports) but was mislabeled `failed` due to a transient Ollama LLM non-response after evidence-gathering was already complete. The root cause was confirmed at `src/agent/agent_loop.py:623-629`: `state.phase` is set to `FAILED` when `_think()` returns `None` twice in a row, even though `_generate_summary()` at line 972 runs unconditionally afterward and can still succeed. This is a reliability/infrastructure limitation (local LLM backend availability), not a reasoning/logic failure of the agent.

### Read-only approval-event check

The following query was run against the local database in read-only mode on 2026-10-14. It identifies the 15 Flow B sessions created on 2026-09-26 and counts approval-related audit rows, including pending `approval_required` rows:

```sql
WITH cohort AS (
  SELECT id FROM agent_sessions
  WHERE playbook_id IS NULL
    AND created_at >= '2026-09-26T00:00:00'
    AND created_at <  '2026-09-27T00:00:00'
), approval_events AS (
  SELECT a.action_type, a.action, a.status, a.requires_approval
  FROM audit_log a JOIN cohort c ON c.id = a.session_id
  WHERE a.requires_approval = 1
     OR a.action_type LIKE 'approval_%'
     OR a.action LIKE 'approval_%'
)
SELECT
  (SELECT COUNT(*) FROM cohort) AS flow_b_sessions,
  (SELECT COUNT(*) FROM approval_events) AS approval_audit_events,
  (SELECT COUNT(*) FROM approval_events WHERE action_type = 'approval_required') AS approval_required,
  (SELECT COUNT(*) FROM approval_events WHERE action_type = 'approval_granted') AS approval_granted,
  (SELECT COUNT(*) FROM approval_events WHERE action_type = 'approval_rejected') AS approval_rejected;
```

Result (`flow_b_sessions, approval_audit_events, approval_required, approval_granted, approval_rejected`): **15, 0, 0, 0, 0**. This verifies the no-approval-event statement for the queried database snapshot and cohort; it does not make `0/0` a measured 0% rate.
