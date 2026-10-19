# Operational metrics — 2026-10-13

## Definitions

For Flow C, each `tool_call` is classified as `success`, `error`, or `unparseable`. A result is `success` when it is a JSON object without a non-null top-level `error`. If a wrapper has `truncated=true`, `ended_in_error=true` means `error`; `false` or a missing value means `success`. Invalid JSON and parsed values that are not objects are `unparseable`.

`step_success_rate = success / (success + error)`. `unparseable` rows are reported separately and are not counted as failures in this denominator. `step_total` includes every `tool_call` row. Errors nested inside an MCP `result` do not change the top-level classification; they are reported separately as `partial_failure_count` with session, step, and tool. `investigate_ioc` rows with `llm_analysis.error` or `sources.*.error` are reported separately as auxiliary information and are not included in `partial_failure_count`.

Flow B continues to count `audit_log` rows with `action_type='tool_call'`, comparing rows with `status='success'` against all tool-call rows, as in the earlier script.

`human_override_rate` counts only audit rows where `requires_approval=1`, `action_type` is `approval_granted` or `approval_rejected`, and `status` is not `pending`; it is rejected decisions divided by completed decisions. When a group contains no sessions, the script emits a 0/0 metric row with rate `0.000000`. The Flow B rows in both CSVs below are empty-group placeholders because both input session lists contain only Flow C sessions. They are not Flow B evaluation results and do not indicate a 0% override rate.

## Cohorts and time ranges

- **As-recorded:** 4 sessions created between `2026-08-30T10:42:35Z` and `2026-09-04T11:36:31Z`. The original metrics CSV is in `evidence/operational_metrics_2026-09-27/`. Session IDs: `2320b6ac573d`, `ab2cb362c774`, `41fa383a6d03`, `b0c0c527cdbb`.
- **Recomputed:** the same session IDs, using full results from session metadata. This is a recalculation, not a new playbook run.
- **Flow C rerun:** IDs in `scripts/adhoc/flow_c_rerun_session_ids.json` (`cc587d2786b6`, `e83135100307`, `8898632cbf7a`, `ee5744705850`, `b1afd5f64a38`, `7a5e681cf418`, `89fc75c9b0fe`, `4a2e030b1cee`) plus `a643cd266adf`, supplied with `--extra-session-id`. All are sessions dated 2026-10-13 according to `agent_sessions`.
- Do not combine the as-recorded and rerun cohorts into one metric.
- The Flow B `0/0` rows in the 2026-09-27 report refer to a different cohort: 15 Flow B sessions. The Flow B `0/0` rows in this report result from having no Flow B sessions in the input lists.

## Results by cohort

As-recorded results from `agent_steps.tool_result`: 15 successes, 0 errors, 5 unparseable rows, and 20 total steps. Excluding unparseable rows, the success rate is 15/15.

The legacy rate reported earlier was 15/20 = 75%, because the old parser counted parse failures as false. This 75% follows the old formula and should not be combined with the revised rate, which excludes unparseable rows from the denominator.

Recomputed by replacing the five truncated rows with full results from `agent_sessions.metadata`: 20 successes, 0 errors, 0 unparseable rows, and 20 total steps; success rate = 20/20. This is a recalculation of the original four sessions, not the nine-session rerun below.

For the Flow C rerun, the attached CSV counts 73/73 `tool_call` steps as successful under the top-level `error` rule. There are 0 unparseable rows and 5/73 nested partial failures (6.8493%), reported separately. Do not describe 73/73 as absence of all errors. `investigate_ioc` also has 7/73 auxiliary errors (9.5890%) according to the CSV. The separate result-size query counted 79 rows because it included both 73 `tool_call` rows and 6 `for_each_iteration` rows; the step-success metric filters to `tool_call` only.

The as-recorded Flow C `human_override_rate` is 0/5 across five approval decisions in the original four sessions. The rerun has 3 rejections among 10 decisions because `--reject-every 3` forced those outcomes. This is a test scenario result, not the actual users' human override rate. Label 0/5 as the as-recorded cohort; do not attach it to the nine-session rerun.

## Reproduction

The database is opened with `mode=ro`. The metrics commands below write CSV reports in this folder and do not write to the database.

```powershell
$env:PYTHONIOENCODING='utf-8'
python evidence/operational_metrics_2026-10-13/compute_operational_metrics.py `
  --session-ids-file scripts/adhoc/flow_c_rerun_session_ids.json `
  --extra-session-id a643cd266adf `
  --label flow-c-rerun `
  --output-csv evidence/operational_metrics_2026-10-13/flow_c_rerun_metrics.csv
```

```powershell
$env:PYTHONIOENCODING='utf-8'
python evidence/operational_metrics_2026-10-13/compute_operational_metrics.py `
  --extra-session-id 2320b6ac573d `
  --extra-session-id ab2cb362c774 `
  --extra-session-id 41fa383a6d03 `
  --extra-session-id b0c0c527cdbb `
  --label flow-c-as-recorded `
  --output-csv evidence/operational_metrics_2026-10-13/flow_c_as_recorded_metrics.csv
```

```powershell
$env:PYTHONIOENCODING='utf-8'
python evidence/operational_metrics_2026-10-13/verify_truncated_rows.py
```

The verification script prints only session, step, tool, flags, serialized length, and prefix-comparison results; it does not print result payloads.
