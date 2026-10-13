# บันทึกงาน reviewer fixes — 2026-10-13

เอกสารนี้รวบรวมหลักฐานใน repository, git, agent.db แบบอ่านอย่างเดียว และประวัติคำสั่งที่ตรวจพบ ณ วันที่ 2026-10-13 งานรอบนี้สร้างเฉพาะไฟล์นี้ ไม่ได้แก้ไฟล์ protocol ที่มีสถานะ modified อยู่ก่อนแล้ว

## 1. ที่มา

| รายการ | ข้อความ / หลักฐาน |
|---|---|
| Reviewer comment 37C | `แก้ Output Truncation Bug ใน Playbook Engine` — ที่มาของชื่อและข้อความ reviewer ตรงนี้มาจากคำสั่งงานในบทสนทนา; ค้นใน `docs/` แล้ว `ไม่พบหลักฐาน` ของไฟล์ต้นฉบับ reviewer |
| Reviewer comment 37B ข้อ 4 และ 37C ข้อ 4 | คำสั่งงานระบุให้เพิ่ม tests สำหรับ Approve/Reject/Timeout/LLM unavailable/tool failure/partial execution และเพิ่ม Flow B/C runs กับ Reject branch; ค้นไฟล์ต้นฉบับ reviewer ใน `docs/` แล้ว `ไม่พบหลักฐาน` |

คำสั่งค้นหาและผลดิบ:

```text
rg -n --glob '*.md' --glob '*.txt' '37C|37B|Output Truncation Bug|Step Success Rate' docs
(ไม่มี output; exit code 1)
```

## 2. Timeline ตามเฟส

### Phase 1 — ตรวจจุดตัด tool output

**เป้าหมาย:** หาจุดตัด `[:10000]` ใน Playbook Engine และยืนยันว่าตัด JSON string ที่ serialize แล้ว

**ไฟล์:** `src/agent/playbook_engine.py`

**คำสั่งที่ตรวจซ้ำกับ parent ของ commit แก้ truncation:**

```powershell
git show 457795c^:src/agent/playbook_engine.py | Select-String -Pattern 'tool_result=.*\[:10000\]' -Context 1,1
```

**ผลดิบ:**

```text
                  tool_params=json.dumps(params, default=str),
>                 tool_result=json.dumps(result, default=str)[:10000],
                  duration_ms=duration_ms,
                  tool_params=json.dumps(params, default=str),
>                 tool_result=json.dumps(result, default=str)[:10000],
                  duration_ms=duration_ms,
                          tool_params=json.dumps(params, default=str),
>                         tool_result=json.dumps(result, default=str)[:10000],
                          duration_ms=duration_ms,
```

**ข้อสรุป:** พบ 3 จุด ทุกจุด serialize ด้วย `json.dumps(...)` ก่อนตัด string ที่ 10,000 ตัวอักษร

**สถานะ:** แก้ใน commit `457795c` โดยเปลี่ยนทั้ง 3 จุดไปใช้ helper เดียว ดู Phase 2

### Phase 1b — ที่มาของ Step Success Rate 98.8% และ 75%

**เป้าหมาย:** ตรวจสูตรและผลเดิมจาก `evidence/operational_metrics_2026-09-27/`

**ไฟล์หลักฐาน:**

- `evidence/operational_metrics_2026-09-27/compute_operational_metrics.py:83-88,120-153`
- `evidence/operational_metrics_2026-09-27/operational_metrics_output.csv`

**โค้ดสูตรดิบ:**

```python
def parse_tool_success(tool_result: Any) -> bool:
    try:
        parsed = json.loads(tool_result)
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(parsed, dict) and "error" not in parsed
```

```python
SELECT tool_result
FROM agent_steps
WHERE step_type = 'tool_call'
  AND session_id IN (...)
step_successes = [parse_tool_success(row[0]) for row in step_rows]
metric_row(group, "step_success_rate", sum(step_successes), len(step_successes))
```

**CSV ดิบ:**

```csv
group,metric,numerator,denominator,rate
Flow B,step_success_rate,85,86,0.988372
Flow B,completion_rate,14,15,0.933333
Flow B,completion_rate_step_limit_abort_breakdown,0,1,0.000000
Flow B,completion_rate_other_non_completed_breakdown,1,1,1.000000
Flow B,human_override_rate,0,0,0.000000
Flow C,step_success_rate,15,20,0.750000
Flow C,completion_rate,4,4,1.000000
Flow C,completion_rate_step_limit_abort_breakdown,0,0,0.000000
Flow C,completion_rate_other_non_completed_breakdown,0,0,0.000000
Flow C,human_override_rate,0,5,0.000000
```

**SELECT/คำนวณใหม่จาก agent.db แบบ mode=ro:** เซสชัน `2320b6ac573d`, `ab2cb362c774`, `41fa383a6d03`, `b0c0c527cdbb`; ตัวเต็มโหลดจาก `agent_sessions.metadata` แล้วแทนเฉพาะแถวที่ผลเดิม parse ไม่ได้

```text
2320b6ac573d 17 investigate_ioc old=0 new=1 full_len=11715
41fa383a6d03 17 investigate_ioc old=0 new=1 full_len=10719
ab2cb362c774 17 investigate_ioc old=0 new=1 full_len=10504
b0c0c527cdbb 2 mcp:remote_tools/process_list_collect old=0 new=1 full_len=20032
b0c0c527cdbb 4 mcp:remote_tools/event_log_collect old=0 new=1 full_len=1574876
TOTAL 15 / 20 -> 20 / 20
```

บรรทัด tool_call อื่นในตารางคำนวณมี `old=1 new=1`; รวม 20 แถว ตารางเต็มพร้อมทุกแถวอยู่ใน raw output ของการคำนวณซ้ำในบทสนทนาวันที่ 2026-10-13

**ข้อสรุป:** สูตรเดิม parse ไม่ได้แล้วนับเป็น false; 5 แถวที่ถูกตัดทำให้ผลเดิม 15/20 และการแทนด้วยผลเต็มจาก metadata ให้ 20/20 ในตัวอย่าง 4 sessions นี้

**สถานะ:** ตรวจย้อนหลังเสร็จ; การปรับสคริปต์ metrics ให้แยก unparseable ยังเป็นงานค้าง ดู §5

### Phase 1c — Approval gate, timeout, audit และ unauthorized

**เป้าหมาย:** ตรวจโค้ดและ tests สำหรับ approval paths

**หลักฐานไฟล์:** `src/agent/playbook_engine.py`, `src/agent/agent_loop.py`, `src/agent/agent_store.py`, `src/web/routes/agent.py`, `tests/test_approval_scenarios.py`

**ผลตรวจที่ยืนยันจาก source/tests ปัจจุบัน:**

- Playbook บันทึก `pending_step_name` และตั้ง session เป็น `waiting_approval` ใน `src/agent/playbook_engine.py:1590-1608`; ไม่พบ timeout ใน playbook pause path ที่ตรวจแล้ว.
- AgentLoop timeout audit assertion อยู่ใน `tests/test_approval_scenarios.py:256-298` และเป็น `xfail(strict=True)` ด้วยเหตุผลที่ระบุว่า timeout ไม่เขียน audit entry และต้องแก้ `agent_loop.py`.
- Unauthorized route tests ที่ `tests/test_approval_scenarios.py:384-407` assert 403/404, tool ไม่ถูกรัน และ `store.get_audit_log(...) == []`.
- `src/agent/agent_store.py:180-203` อัปเดต session status ด้วย `UPDATE ... WHERE id = ?`; ไม่พบ compare-and-set เงื่อนไข status ในเมธอดนี้. `update_session_metadata` เริ่มที่บรรทัด 225.
- Route ใช้ `current_user.get("username") or current_user.get("email") or "unknown"` ที่ `src/web/routes/agent.py:336` แล้วส่ง `approved_by` ที่ได้ให้ทั้ง playbook และ AgentLoop ที่บรรทัด 344-356.

**คำสั่งที่ยืนยันได้:** ดูคำสั่ง targeted pytest ใน §6; raw ผลรอบแรก Phase 1c แยกต่างหาก `ไม่พบหลักฐาน`

**ข้อสรุป:** เส้นทางที่ตรวจพบครอบคลุมทั้ง approve/reject; ข้อจำกัด timeout/audit, ownership audit และ CAS บันทึกไว้ใน §4

**สถานะ:** ตรวจโค้ดและเพิ่ม scenario tests แล้ว; timeout audit ยังไม่แก้เพราะอยู่นอกขอบเขต Phase 5

### Phase 4 — Scenario tests

**เป้าหมาย:** เพิ่ม `tests/test_approval_scenarios.py` สำหรับ rejection, repeated resume, nonwaiting session, partial execution, tool errors, nested error, timeout และ route authorization

**ไฟล์:** `tests/test_approval_scenarios.py` — เพิ่มใน commit `b078553` (ดู `git show --stat` ใน §2)

**ผลดิบรอบแรก:**

```text
ไม่พบหลักฐาน — ไม่พบ raw pytest log ของการรันครั้งแรกในไฟล์ repository หรือ PowerShell history ที่ตรวจได้
```

คำสั่งงานระบุผลรอบแรกเป็น `5 failed / 7 passed` แต่เมื่อไม่มี raw log ให้ตรวจสอบ เอกสารนี้ไม่รับรองตัวเลขดังกล่าว

**ผลดิบที่ยืนยันได้หลังเพิ่ม xfail strict:** ในการรัน targeted 3 suites Phase 2b รายงาน `23 passed, 1 xfailed`; รอบ Phase 2c รัน storage suite รายงาน `7 passed` (คำสั่งอยู่ใน §6)

**ข้อสรุป:** test file มี test cases ตาม source ปัจจุบัน; ผลรอบแรกที่ขอมา `ไม่พบหลักฐาน` แบบ raw

**สถานะ:** test file committed ใน `b078553`; timeout audit assertion คงเป็น xfail strict

### Phase 5 และ 5b — Approval resume guard และ approver identity

**เป้าหมาย:** ป้องกัน resume ซ้ำ/ข้ามสถานะ และไม่รับชื่อผู้อนุมัติจาก request body

**ไฟล์:** `src/agent/playbook_engine.py`, `src/web/routes/agent.py`, `tests/test_approval_scenarios.py`

**raw diff สำคัญจาก commit `3bd8c95`:**

```diff
+        if session.get("status") != "waiting_approval":
+            raise ValueError(
+                f"Session '{session_id}' has no pending approval checkpoint to resume"
+            )
...
+        self.store.update_session_status(session_id, "active")
+        claimed_metadata = dict(metadata)
+        claimed_metadata.pop("pending_step_name", None)
+        self.store.update_session_metadata(session_id, claimed_metadata)
...
+    approved_by = current_user.get("username") or current_user.get("email") or "unknown"
...
-            await playbook_engine.execute_from_step(session_id, approved=body.approved, approved_by=body.approved_by)
+            await playbook_engine.execute_from_step(
+                session_id, approved=body.approved, approved_by=approved_by,
+            )
...
-            success = await agent_loop.approve_action(session_id, approved_by=body.approved_by)
+            success = await agent_loop.approve_action(session_id, approved_by=approved_by)
```

Phase 5b คง error สำหรับ session ที่ไม่มีอยู่เป็น `Session '{session_id}' not found`; `execute_from_step` ตรวจ `waiting_approval`, ตั้ง `active`, ล้าง `pending_step_name` ก่อน dispatch tool. อย่างไรก็ตาม store API เป็น ordinary update; ไม่ใช่ atomic compare-and-set.

**Test timeout audit:** `tests/test_approval_scenarios.py:256-259` มี `@pytest.mark.xfail(strict=True, reason="approval timeout writes no audit entry; fix requires agent_loop.py (near-forbidden)")`; assertion ที่ตามมายังคงตรวจ `timeout_entries` ว่ามีค่า

**ผลดิบ targeted tests ของ Phase 5/5b:** `ไม่พบหลักฐาน` สำหรับ raw output แยกของรอบนั้น; ผลที่ยืนยันได้ของชุด tests หลังปรับ xfail คือ 23 passed, 1 xfailed ในรอบ Phase 2b

**สถานะ:** commit `3bd8c95`; tests เพิ่มใน `b078553`; รายละเอียด commit อยู่ใน §2

### Phase 1d — อ่านโค้ดก่อน Phase 5

**เป้าหมาย:** อ่าน `execute_from_step`, session store methods และ route handlers ก่อนทำ guard

**ผล source ที่ตรวจได้ย้อนหลัง:**

- `execute_from_step` อยู่ใน `src/agent/playbook_engine.py` เริ่มประมาณบรรทัด 1194; หลัง Phase 5 guard อยู่บรรทัด 1209-1233.
- Store มี `update_session_status` และ `update_session_metadata` (`src/agent/agent_store.py:180-203,225-...`); ไม่พบ API compare-and-set ในเมธอดเหล่านี้.
- Route approve/reject เป็น handler เดียว `src/web/routes/agent.py:317-357`, แยก playbook กับ AgentLoop จาก metadata.

**raw output ของการอ่านก่อนแก้ใน Phase 1d:** `ไม่พบหลักฐาน` แยกจาก diff commit; ใช้ diff `3bd8c95` ด้านบนเป็นหลักฐานการเปลี่ยนแปลงเท่านั้น

**สถานะ:** ตรวจย้อนหลังจาก source/diff แล้ว

### Phase 2 — จัดเก็บ tool result เป็น JSON ที่ parse ได้

**เป้าหมาย:** เปลี่ยนสามจุด truncation ไปใช้ `_serialize_tool_result` และเพิ่ม tests

**ไฟล์:** `src/agent/playbook_engine.py`, `tests/test_playbook_tool_result_storage.py`

**commit:** `457795c` — `Store complete playbook tool results; valid JSON wrapper on oversize`

**diff ดิบของ helper และหนึ่งในสาม call sites (อีกสอง call sites ทำการแทนที่เดียวกัน):**

```diff
+_MAX_STORED_TOOL_RESULT_CHARS = 5_000_000
+
+def _serialize_tool_result(result: Any) -> str:
+    """Serialize tool output for storage, preserving valid JSON when shortened."""
+    serialized = json.dumps(result, default=str)
+    if len(serialized) <= _MAX_STORED_TOOL_RESULT_CHARS:
+        return serialized
+    return json.dumps({
+        "truncated": True,
+        "original_size": len(serialized),
+        "ended_in_error": _tool_call_ended_in_error(result),
+        "preview": serialized[:10_000],
+    })
...
-                tool_result=json.dumps(result, default=str)[:10000],
+                tool_result=_serialize_tool_result(result),
```

wrapper มี `truncated`, `original_size`, `ended_in_error`, `preview`; มี JSON ชั้นนอกที่ parse ได้ และไม่มี `error` ระดับบนสุด. predicate `ended_in_error` ใช้ `_tool_call_ended_in_error` ที่มีอยู่ใน engine.

**เพดาน:** ใน commit `457795c` และ source ปัจจุบันเป็น `5_000_000` ตัวอักษร; ขั้นก่อนหน้าที่เคยตั้ง `1_000_000` มีอยู่ในประวัติการทำงานตามคำสั่งก่อนหน้า แต่ raw diff/commit เฉพาะการเปลี่ยน 1,000,000 → 5,000,000 `ไม่พบหลักฐาน` ใน git history ปัจจุบัน (ไฟล์ปัจจุบันตรงกับ commit แล้ว)

**Tests:** `tests/test_playbook_tool_result_storage.py` เพิ่ม 187 บรรทัดใน commit `457795c`; raw output ที่ยืนยันได้: targeted Phase 2b 23 passed, 1 xfailed; Phase 2c storage test 7 passed

**สถานะ:** commit `457795c`; helper เดียวแทนทั้งสามจุด

### ตรวจผลเต็มย้อนหลังใน metadata

**เป้าหมาย:** เปรียบเทียบผลเก็บเดิมกับผลเต็มใน `agent_sessions.metadata` สำหรับ 4 sessions

**หลักฐาน DB:** เปิด `C:\Users\ACER\.blue-team-assistant\cache\agent.db` ด้วย URI `mode=ro`; ไม่พิมพ์ค่า IOC, ข้อมูล event log หรือข้อมูลผลเต็ม

**ผลดิบ metadata keys และความยาวผลเต็ม:**

```text
SESSION 2320b6ac573d metadata_keys= ['ioc', 'ioc_investigation_result'] context_keys= []
SESSION ab2cb362c774 metadata_keys= ['ioc', 'ioc_investigation_result'] context_keys= []
SESSION 41fa383a6d03 metadata_keys= ['ioc', 'ioc_investigation_result'] context_keys= []
SESSION b0c0c527cdbb metadata_keys= ['case_id', 'context', 'pending_step_name', 'step_number'] context_keys= [...]
FULL_RESULT 2320b6ac573d ioc_investigation_result len= 11715 top_error= False
FULL_RESULT ab2cb362c774 ioc_investigation_result len= 10504 top_error= False
FULL_RESULT 41fa383a6d03 ioc_investigation_result len= 10719 top_error= False
FULL_RESULT b0c0c527cdbb context.collect_running_processes len= 20032 top_error= False
FULL_RESULT b0c0c527cdbb context.collect_event_logs len= 1574876 top_error= False
TOTAL 15 / 20 -> 20 / 20
```

ความยาวเป็น `len(json.dumps(result, default=str))` ตามการคำนวณ; forensic ผลเป็น MCP envelope `{"result": {...}, "server": ..., "tool": ...}`. ผลเต็มของ process list และ event log ถูกอ่านจาก `metadata.context` ตามชื่อ step; IOC results อยู่ที่ `metadata.ioc_investigation_result`.

**สถานะ:** ตรวจซ้ำ read-only เสร็จ; ตัวเลข 20/20 เป็นการคำนวณใหม่จาก full result และ predicate เดิม ไม่ใช่ผลจาก rerun ของ playbook

### ขนาดผลกับ step projection

**ไฟล์:** `src/web/step_projection.py:20,38-59`

```python
MAX_RESULT_JSON = 65_536
...
def _decode_result(value: Any) -> dict[str, Any] | None:
    """Decode at most one JSON string layer and one MCP result envelope."""
    if isinstance(value, str):
        if len(value) > MAX_RESULT_JSON:
            return None
```

**ผลที่ยืนยันจาก metadata:** investigate_ioc ที่มีผลเต็ม 10,504–11,715 ตัวอักษร ต่ำกว่า 65,536; event log 1,574,876 ตัวอักษร สูงกว่า 65,536. จำนวนผลจริงของ IOC รอบทดสอบแยกจาก DB ก้อนนี้ `ไม่พบหลักฐาน` ใน work log นี้

**สถานะ:** พบเพดานฝั่ง projection แยกจากเพดาน storage

### Commits และ full pytest

**`git log --oneline -n 10` ผลดิบ:**

```text
457795c Store complete playbook tool results; valid JSON wrapper on oversize
b078553 Add approval scenario tests
3bd8c95 Approval resume guard and authenticated approver
ba52283 docs: finalize protocol evidence tables (C2, ThreatFox, Tranco, smoke) and old-holdout checks
9d2571c eval: add offline sensitivity analysis (weights, consensus multiplier, thresholds)
420d4b1 docs: record evaluation run evidence, trusted-shortcut and coverage findings in protocol
38978cd data: keep small raw source snapshots for independent URL holdout
7e7b59d data: record single evaluation run and metrics for independent URL holdout
5dc60fa data: freeze independent URL holdout (256 rows) and overlap measurement before evaluation
8d42c6b eval: add specificity/Wilson CI and per-expected verdict counts; record overlap/unknown rules before evaluation
```

**`git show --stat --oneline --no-renames` ผลดิบ:**

```text
3bd8c95 Approval resume guard and authenticated approver
 src/agent/playbook_engine.py | 14 ++++++++++++--
 src/web/routes/agent.py      |  9 ++++++---
 2 files changed, 18 insertions(+), 5 deletions(-)

b078553 Add approval scenario tests
 tests/test_approval_scenarios.py | 407 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 407 insertions(+)

457795c Store complete playbook tool results; valid JSON wrapper on oversize
 src/agent/playbook_engine.py               |  22 +++-
 tests/test_playbook_tool_result_storage.py | 187 +++++++++++++++++++++++++++++
 2 files changed, 206 insertions(+), 3 deletions(-)
```

ผล full pytest ที่มีการกล่าวถึงว่า `3339 passed, 1 skipped, 1 xfailed` แต่ raw output / log ที่ยืนยันตัวเลขนี้ `ไม่พบหลักฐาน` ใน repository หรือประวัติคำสั่งที่ตรวจได้

### Flow C rerun และ DB read-only check

**ไฟล์:** `scripts/adhoc/generate_flow_c_sessions.py`, `scripts/adhoc/flow_c_rerun_session_ids.json`; path `scripts/adhoc/` อยู่ใน gitignore (`.gitignore:146`).

**การตรวจฐานข้อมูล:** SELECT แบบ read-only; session IDs ที่ตรวจได้:

```text
cc587d2786b6
e83135100307
8898632cbf7a
ee5744705850
b1afd5f64a38
7a5e681cf418
89fc75c9b0fe
4a2e030b1cee
a643cd266adf
```

**ผลดิบ:**

```text
tool_call_rows= 73 unparseable= 0 wrapper= 0 nested_error= 5 nested_by_tool= {'mcp:osint_tools/reverse_dns': 1, 'mcp:osint_tools/subdomain_enumerate': 2, 'mcp:free_osint_tools/crtsh_subdomain_search': 2} largest= (515903, 'mcp:remote_tools/event_log_collect')
(79, 515903, 0, None)
('approval_granted', 'human', 'admin', 'success', 7)
('approval_rejected', 'human', 'admin', 'rejected', 3)
('approval_required', 'system', None, 'pending', 10)
('89fc75c9b0fe', 4, 'mcp:remote_tools/event_log_collect', 515903)
```

ค่าทูเพิล `(79, 515903, 0, None)` เป็น `COUNT, MAX(length(tool_result)), SUM(json_valid(...)=0), SUM(json_extract(...,'$.truncated')=1)` สำหรับ `tool_call` และ `for_each_iteration`; ค่า wrapper ที่ SQL aggregate คืน `NULL` เพราะไม่มีแถวที่ expression เป็นจริง ไม่ได้ตีความเป็นจำนวนโดยไม่ระบุบริบท. การนับ Python บน 73 tool_call rows แสดง `wrapper=0`.

การที่สคริปต์ถูก compile และ `--dry-run` ผ่านมีบันทึกผลก่อน rerun; แต่คำสั่ง exact ที่เรียก API เพื่อสร้าง Flow C sessions (รวม args, ไม่รวม secret) และ log การรันสคริปต์จริง `ไม่พบหลักฐาน` ใน PowerShell history ที่ตรวจได้. IDs/DB rows ยืนยันว่ามี sessions ที่ระบุข้างต้น แต่เพียงอย่างเดียวไม่ยثبتว่าสคริปต์ไฟล์นี้เป็นผู้สร้าง

**สถานะ:** มี sessions และ audit rows ตาม SELECT; execution command provenance `ไม่พบหลักฐาน`

## 3. ตารางหลักฐานสรุป

| ข้อเท็จจริง | ตัวเลข/ผล | แหล่งที่มา | วิธีตรวจซ้ำ |
|---|---:|---|---|
| Truncation เดิมใน playbook engine | 3 จุด, 10,000 ตัวอักษร | parent ของ `457795c`, `src/agent/playbook_engine.py` | `git show 457795c^:src/agent/playbook_engine.py` แล้วค้น `tool_result=.*[:10000]` |
| Step Success Rate Flow B | 85/86 = 0.988372 | `evidence/operational_metrics_2026-09-27/operational_metrics_output.csv` | อ่าน CSV และสูตรใน `compute_operational_metrics.py:83-88,133-142` |
| Step Success Rate Flow C เดิม | 15/20 = 0.750000 | CSV เดียวกัน | อ่าน CSV และ `compute_operational_metrics.py:120-153` |
| Recompute 4 sessions จากผลเต็ม | 15/20 → 20/20 | `agent.db` metadata + tool_result; session ids ใน §2 | SQLite `mode=ro`, deserialize metadata, predicate `dict and "error" not in result` |
| Full investigate_ioc lengths | 11,715; 10,504; 10,719 | `agent_sessions.metadata.ioc_investigation_result` | SELECT metadata แบบ read-only, `len(json.dumps(result, default=str))` |
| Full forensic result lengths | 20,032; 1,574,876 | `agent_sessions.metadata.context` | SELECT metadata แบบ read-only ตาม key ของ step |
| Projection cap | 65,536 | `src/web/step_projection.py:20,38-45` | อ่าน constant และ `_decode_result` |
| Current stored-result cap | 5,000,000 | `src/agent/playbook_engine.py:34` ที่ commit `457795c` | `git show 457795c:src/agent/playbook_engine.py` |
| Targeted Phase 2b tests | 23 passed, 1 xfailed | raw pytest output ในบทสนทนาวันที่ 2026-10-13 | คำสั่งใน §6 |
| Targeted Phase 2c storage test | 7 passed | raw pytest output ในบทสนทนาวันที่ 2026-10-13 | คำสั่งใน §6 |
| Flow C read-only | 73 tool_call, invalid 0, wrapper 0, nested error 5; max 515,903 | `agent.db` | query/การนับ Python แบบ mode=ro ใน §2 |
| Audit Flow C | required 10, granted 7, rejected 3; approved_by `admin` | `agent.db` | SELECT group by action_type, actor, approved_by, status |
| Full pytest | `3339 passed, 1 skipped, 1 xfailed` | ไม่พบ raw log | ไม่พบหลักฐาน |

## 4. ข้อจำกัดที่รู้แล้ว

- Approval timeout ของ AgentLoop ไม่มี audit entry ตามเหตุผล xfail strict ที่ `tests/test_approval_scenarios.py:256-259`; การแก้ต้องแตะ `src/agent/agent_loop.py`.
- Playbook approval path บันทึก `waiting_approval` แล้ว return (`src/agent/playbook_engine.py:1590-1608`); ไม่พบหลักฐานว่ามี timeout.
- Approval claim ไม่ใช่ compare-and-set: `update_session_status` เป็น `UPDATE ... WHERE id = ?` ใน `src/agent/agent_store.py:180-203`.
- การพยายาม approve ที่ถูกปฏิเสธ 403/404 ไม่ถูกบันทึกใน audit ตาม test ที่ assert `store.get_audit_log(...) == []` (`tests/test_approval_scenarios.py:392-407`).
- Metric `parse_tool_success` นับเฉพาะการ parse dict และไม่มี key `error` ที่ top level (`compute_operational_metrics.py:83-88`); nested errors ไม่ทำให้ fail ตามสูตรนี้ และ Flow C rerun แยกพบ nested errors 5 rows.
- Reject ที่สคริปต์ตั้งด้วย `--reject-every` เป็นการเลือกกิ่งทดสอบแบบกำหนดล่วงหน้า ไม่ใช่ Human Override Rate จริง.
- ตัวอย่างผลย้อนหลัง 4 sessions; Flow C rerun มี session IDs 9 รายการที่ตรวจจาก DB. ตัวอย่างยังเล็กสำหรับอ้างอัตราทั่วไป.

## 5. งานที่ยังค้าง

- Phase 3: สร้างสคริปต์ metrics ใน `evidence/operational_metrics_2026-10-13/` เพื่อแยก success/error/unparseable.
- เขียนคำตอบ reviewer สำหรับ 37B/37C โดยอ้างหลักฐานและตัวเลขที่ตรวจซ้ำได้.
- ปรับข้อความใต้ Table 3 ให้ใช้คำว่า `characters` ไม่ใช่ `bytes`; การแก้ protocol ไม่ได้ทำในงานสร้าง work log นี้.
- ตัดสินใจว่าจะอนุญาตให้แก้ `agent_loop.py` เพื่อเพิ่ม approval timeout audit หรือไม่.
- ตรวจสอบ full pytest summary `3339 passed, 1 skipped, 1 xfailed` จาก raw log: `ไม่พบหลักฐาน`.
- ยืนยัน command provenance ของการ rerun Flow C จาก shell history/log: `ไม่พบหลักฐาน`.

## 6. วิธีทำซ้ำจากหลักฐานที่มี

รายการนี้แยกคำสั่งที่มีหลักฐานการรันออกจากขั้นตอนที่ไม่มี transcript ยืนยัน ห้ามใช้ credential หรือพิมพ์ IOC/event-log payload ลง log

### ตรวจ commits / source

```powershell
git log --oneline -n 10
git show --stat --oneline --no-renames 3bd8c95
git show --stat --oneline --no-renames b078553
git show --stat --oneline --no-renames 457795c
git show 457795c^:src/agent/playbook_engine.py | Select-String -Pattern 'tool_result=.*\[:10000\]' -Context 1,1
```

### DB สำรองและเปิด server

ใน PowerShell history พบคำสั่งเริ่ม Uvicorn หลายรายการ แต่ไม่พบหลักฐานว่าเป็นการ restart server สำหรับ Flow C rerun นี้. คำสั่งสำรอง DB ก่อน rerun `ไม่พบหลักฐาน`; ห้ามถือว่ามีการสำรองแล้ว

```text
python -m uvicorn src.web.app:create_app --factory --host 127.0.0.1 --port 3003
```

คำสั่งข้างต้นเป็น raw command ที่พบใน PSReadLine history; timestamp/context ที่เชื่อมกับ rerun นี้ `ไม่พบหลักฐาน`.

### สคริปต์ Flow C

ตัวไฟล์และ JSON session ids มีอยู่ใน ignored path. คำสั่ง exact ที่รันสคริปต์จริงเพื่อเรียก endpoint `ไม่พบหลักฐาน`; ไม่มี credential หรือ request args ในเอกสารนี้. ผล DB ที่ได้ตรวจซ้ำด้วย SQLite read-only แล้วอยู่ใน §2.

### SELECT read-only สำหรับ Flow C

```sql
SELECT COUNT(*) AS rows_total,
       MAX(length(tool_result)) AS max_len,
       SUM(json_valid(tool_result)=0) AS invalid_json,
       COALESCE(SUM(json_extract(tool_result,'$.truncated')=1),0) AS wrapper_rows
FROM agent_steps
WHERE step_type IN ('tool_call','for_each_iteration')
  AND session_id IN (?, ?, ?, ?, ?, ?, ?, ?, ?);

SELECT action_type, actor, approved_by, status, COUNT(*)
FROM audit_log
WHERE session_id IN (?, ?, ?, ?, ?, ?, ?, ?, ?)
GROUP BY 1,2,3,4;
```

เปิด DB ด้วย SQLite URI `mode=ro`; session IDs ที่ใช้แสดงใน §2. ผล query ในการตรวจรอบนี้: `rows_total=79`, `max_len=515903`, `invalid_json=0`; Python count ใน 73 tool_call rows ให้ `wrapper=0`; audit groups แสดง approval_required=10, approval_granted=7, approval_rejected=3 และ `approved_by=admin` สำหรับ granted/rejected.

### Targeted pytest ที่มีหลักฐาน raw output

```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/test_playbook_tool_result_storage.py tests/test_approval_scenarios.py tests/test_for_each_approval_resume.py --basetemp="$env:TEMP\p2b" -p no:cacheprovider
```

```text
23 passed, 1 xfailed
```

```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/test_playbook_tool_result_storage.py --basetemp="$env:TEMP\p2c" -p no:cacheprovider
```

```text
7 passed
```

คำสั่ง targeted สำหรับ tests 4 ไฟล์ใน Phase 5b และ output แบบเต็มของ Phase 4 ครั้งแรก `ไม่พบหลักฐาน` ใน raw log ที่ตรวจได้. ไม่มีการรัน full pytest ในการทำ work log นี้.

## บันทึกต่อ


### Phase 3 — Operational metrics แบบ 3 สถานะ

ไฟล์ที่เพิ่มใน `evidence/operational_metrics_2026-10-13/`: `compute_operational_metrics.py`, `verify_truncated_rows.py`, `README.md`, `flow_c_as_recorded_metrics.csv`, `flow_c_rerun_metrics.csv`. เพิ่ม `.gitignore` exception สำหรับ directory นี้. `compute_operational_metrics.py` แบ่ง Flow C เป็น success/error/unparseable; error ซ้อนใน MCP result และ error ภายใน investigate_ioc รายงานแยก. Flow B ยังคงใช้ audit_log status.

คำสั่งที่รันจริง:

```powershell
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe evidence/operational_metrics_2026-10-13/compute_operational_metrics.py --extra-session-id 2320b6ac573d --extra-session-id ab2cb362c774 --extra-session-id 41fa383a6d03 --extra-session-id b0c0c527cdbb --label flow-c-as-recorded --output-csv evidence/operational_metrics_2026-10-13/flow_c_as_recorded_metrics.csv
.\.venv\Scripts\python.exe evidence/operational_metrics_2026-10-13/compute_operational_metrics.py --session-ids-file scripts/adhoc/flow_c_rerun_session_ids.json --extra-session-id a643cd266adf --label flow-c-rerun --output-csv evidence/operational_metrics_2026-10-13/flow_c_rerun_metrics.csv
.\.venv\Scripts\python.exe evidence/operational_metrics_2026-10-13/verify_truncated_rows.py
```

ผลดิบของ `compute_operational_metrics.py` สำหรับ as-recorded:

```text
group | metric | numerator | denominator | rate | details
Flow B | step_success_rate | 0 | 0 | 0.000000 |
Flow B | completion_rate | 0 | 0 | 0.000000 |
Flow B | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
Flow B | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
Flow B | human_override_rate | 0 | 0 | 0.000000 |
Flow C [flow-c-as-recorded] | step_success_rate | 15 | 15 | 1.000000 |
Flow C [flow-c-as-recorded] | error_count | 0 | 20 | 0.000000 |
Flow C [flow-c-as-recorded] | unparseable_count | 5 | 20 | 0.250000 |
Flow C [flow-c-as-recorded] | step_total | 20 | 20 | 1.000000 |
Flow C [flow-c-as-recorded] | partial_failure_count | 0 | 15 | 0.000000 |
Flow C [flow-c-as-recorded] | investigate_ioc_auxiliary_error_count | 0 | 20 | 0.000000 |
Flow C | completion_rate | 4 | 4 | 1.000000 |
Flow C | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
Flow C | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
Flow C | human_override_rate | 0 | 5 | 0.000000 |
csv_path=evidence/operational_metrics_2026-10-13/flow_c_as_recorded_metrics.csv
```

ผลดิบของ `compute_operational_metrics.py` สำหรับ rerun (session-id file บวก `a643cd266adf`):

```text
group | metric | numerator | denominator | rate | details
Flow B | step_success_rate | 0 | 0 | 0.000000 |
Flow B | completion_rate | 0 | 0 | 0.000000 |
Flow B | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
Flow B | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
Flow B | human_override_rate | 0 | 0 | 0.000000 |
Flow C [flow-c-rerun] | step_success_rate | 73 | 73 | 1.000000 |
Flow C [flow-c-rerun] | error_count | 0 | 73 | 0.000000 |
Flow C [flow-c-rerun] | unparseable_count | 0 | 73 | 0.000000 |
Flow C [flow-c-rerun] | step_total | 73 | 73 | 1.000000 |
Flow C [flow-c-rerun] | partial_failure_count | 5 | 73 | 0.068493 | 7a5e681cf418:3:mcp:osint_tools/reverse_dns;b1afd5f64a38:10:mcp:osint_tools/subdomain_enumerate;b1afd5f64a38:12:mcp:free_osint_tools/crtsh_subdomain_search;e83135100307:10:mcp:osint_tools/subdomain_enumerate;e83135100307:12:mcp:free_osint_tools/crtsh_subdomain_search
Flow C [flow-c-rerun] | investigate_ioc_auxiliary_error_count | 7 | 73 | 0.095890 | 7a5e681cf418:17:investigate_ioc;8898632cbf7a:17:investigate_ioc;a643cd266adf:17:investigate_ioc;b1afd5f64a38:17:investigate_ioc;cc587d2786b6:17:investigate_ioc;e83135100307:17:investigate_ioc;ee5744705850:17:investigate_ioc
Flow C | completion_rate | 9 | 9 | 1.000000 |
Flow C | completion_rate_step_limit_abort_breakdown | 0 | 0 | 0.000000 |
Flow C | completion_rate_other_non_completed_breakdown | 0 | 0 | 0.000000 |
Flow C | human_override_rate | 3 | 10 | 0.300000 |
partial_failure_tool | 7a5e681cf418 | 3 | mcp:osint_tools/reverse_dns
partial_failure_tool | b1afd5f64a38 | 10 | mcp:osint_tools/subdomain_enumerate
partial_failure_tool | b1afd5f64a38 | 12 | mcp:free_osint_tools/crtsh_subdomain_search
partial_failure_tool | e83135100307 | 10 | mcp:osint_tools/subdomain_enumerate
partial_failure_tool | e83135100307 | 12 | mcp:free_osint_tools/crtsh_subdomain_search
investigate_ioc_auxiliary_error | 7a5e681cf418 | 17 | investigate_ioc
investigate_ioc_auxiliary_error | 8898632cbf7a | 17 | investigate_ioc
investigate_ioc_auxiliary_error | a643cd266adf | 17 | investigate_ioc
investigate_ioc_auxiliary_error | b1afd5f64a38 | 17 | investigate_ioc
investigate_ioc_auxiliary_error | cc587d2786b6 | 17 | investigate_ioc
investigate_ioc_auxiliary_error | e83135100307 | 17 | investigate_ioc
investigate_ioc_auxiliary_error | ee5744705850 | 17 | investigate_ioc
csv_path=evidence/operational_metrics_2026-10-13/flow_c_rerun_metrics.csv
```

ผลดิบของ `verify_truncated_rows.py`:

```text
session_id,step_number,tool_name,old_success,new_success,full_len,serialized_prefix_matches_truncated
2320b6ac573d,1,extract_iocs,1,1,,n/a
2320b6ac573d,14,mcp:threat_intel_tools/urlhaus_lookup,1,1,,n/a
2320b6ac573d,16,mcp:threat_intel_tools/threatfox_ioc_lookup,1,1,,n/a
2320b6ac573d,17,investigate_ioc,0,1,11715,true
41fa383a6d03,1,extract_iocs,1,1,,n/a
41fa383a6d03,14,mcp:threat_intel_tools/urlhaus_lookup,1,1,,n/a
41fa383a6d03,16,mcp:threat_intel_tools/threatfox_ioc_lookup,1,1,,n/a
41fa383a6d03,17,investigate_ioc,0,1,10719,true
41fa383a6d03,19,generate_rules,1,1,,n/a
ab2cb362c774,1,extract_iocs,1,1,,n/a
ab2cb362c774,14,mcp:threat_intel_tools/urlhaus_lookup,1,1,,n/a
ab2cb362c774,16,mcp:threat_intel_tools/threatfox_ioc_lookup,1,1,,n/a
ab2cb362c774,17,investigate_ioc,0,1,10504,true
b0c0c527cdbb,1,mcp:remote_tools/system_info_collect,1,1,,n/a
b0c0c527cdbb,2,mcp:remote_tools/process_list_collect,0,1,20032,true
b0c0c527cdbb,3,mcp:remote_tools/netstat_collect,1,1,,n/a
b0c0c527cdbb,4,mcp:remote_tools/event_log_collect,0,1,1574876,true
b0c0c527cdbb,6,mcp:remote_tools/autoruns_check,1,1,,n/a
b0c0c527cdbb,10,extract_iocs,1,1,,n/a
b0c0c527cdbb,12,mcp:forensics_tools/mitre_attack_mapper,1,1,,n/a
SUMMARY old_success=15/20 new_success=20/20
```

raw CSV `flow_c_as_recorded_metrics.csv`:

```csv
group,metric,numerator,denominator,rate,details
Flow B,step_success_rate,0,0,0.000000,
Flow B,completion_rate,0,0,0.000000,
Flow B,completion_rate_step_limit_abort_breakdown,0,0,0.000000,
Flow B,completion_rate_other_non_completed_breakdown,0,0,0.000000,
Flow B,human_override_rate,0,0,0.000000,
Flow C [flow-c-as-recorded],step_success_rate,15,15,1.000000,
Flow C [flow-c-as-recorded],error_count,0,20,0.000000,
Flow C [flow-c-as-recorded],unparseable_count,5,20,0.250000,
Flow C [flow-c-as-recorded],step_total,20,20,1.000000,
Flow C [flow-c-as-recorded],partial_failure_count,0,15,0.000000,
Flow C [flow-c-as-recorded],investigate_ioc_auxiliary_error_count,0,20,0.000000,
Flow C,completion_rate,4,4,1.000000,
Flow C,completion_rate_step_limit_abort_breakdown,0,0,0.000000,
Flow C,completion_rate_other_non_completed_breakdown,0,0,0.000000,
Flow C,human_override_rate,0,5,0.000000,
```

raw CSV `flow_c_rerun_metrics.csv`:

```csv
group,metric,numerator,denominator,rate,details
Flow B,step_success_rate,0,0,0.000000,
Flow B,completion_rate,0,0,0.000000,
Flow B,completion_rate_step_limit_abort_breakdown,0,0,0.000000,
Flow B,completion_rate_other_non_completed_breakdown,0,0,0.000000,
Flow B,human_override_rate,0,0,0.000000,
Flow C [flow-c-rerun],step_success_rate,73,73,1.000000,
Flow C [flow-c-rerun],error_count,0,73,0.000000,
Flow C [flow-c-rerun],unparseable_count,0,73,0.000000,
Flow C [flow-c-rerun],step_total,73,73,1.000000,
Flow C [flow-c-rerun],partial_failure_count,5,73,0.068493,7a5e681cf418:3:mcp:osint_tools/reverse_dns;b1afd5f64a38:10:mcp:osint_tools/subdomain_enumerate;b1afd5f64a38:12:mcp:free_osint_tools/crtsh_subdomain_search;e83135100307:10:mcp:osint_tools/subdomain_enumerate;e83135100307:12:mcp:free_osint_tools/crtsh_subdomain_search
Flow C [flow-c-rerun],investigate_ioc_auxiliary_error_count,7,73,0.095890,7a5e681cf418:17:investigate_ioc;8898632cbf7a:17:investigate_ioc;a643cd266adf:17:investigate_ioc;b1afd5f64a38:17:investigate_ioc;cc587d2786b6:17:investigate_ioc;e83135100307:17:investigate_ioc;ee5744705850:17:investigate_ioc
Flow C,completion_rate,9,9,1.000000,
Flow C,completion_rate_step_limit_abort_breakdown,0,0,0.000000,
Flow C,completion_rate_other_non_completed_breakdown,0,0,0.000000,
Flow C,human_override_rate,3,10,0.300000,
```

ผล `git check-ignore` ใช้ `-v -n --no-index`; ทุก path แสดง `::` (ไม่มี ignore rule ที่จับ path) และ exit 1 ซึ่งหมายถึงไม่มี path ใดถูก ignore:

```text
::	evidence/operational_metrics_2026-10-13/compute_operational_metrics.py
::	evidence/operational_metrics_2026-10-13/verify_truncated_rows.py
::	evidence/operational_metrics_2026-10-13/README.md
::	evidence/operational_metrics_2026-10-13/flow_c_as_recorded_metrics.csv
::	evidence/operational_metrics_2026-10-13/flow_c_rerun_metrics.csv
CHECK_IGNORE_EXIT=1
```

**สถานะ Phase 3:** สคริปต์ทั้งสองรันผ่าน; verifier ได้ 15/20 → 20/20 และทุก prefix comparison ของ 5 แถวเป็น true. ไม่ได้รัน pytest หรือ full pytest. Reject 3 ครั้งยังเป็น branch ที่บังคับด้วย `--reject-every`, ไม่ใช่ Human Override Rate จริง.

**งานที่ยังค้างต่อจากนี้:** เพิ่มสคริปต์ metrics เสร็จแล้ว; ยังเหลือคำตอบ reviewer 37B/37C, การแก้ข้อความใต้ Table 3 ให้ใช้ `characters` แทน `bytes`, และการตัดสินใจเรื่องเพิ่ม timeout audit ใน `agent_loop.py`.