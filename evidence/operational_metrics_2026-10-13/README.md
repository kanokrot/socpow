# Operational metrics — 2026-10-13

## นิยาม

Flow C จัดผลแต่ละ tool_call เป็น `success`, `error` หรือ `unparseable`. success คือ JSON object ที่ไม่มี `error` ซึ่งไม่ใช่ null ที่ระดับบนสุด. wrapper ที่ `truncated=true` ใช้ `ended_in_error`: true เป็น error, false หรือไม่มีค่าเป็น success. JSON ที่ parse ไม่ได้หรือ parsed value ที่ไม่ใช่ object เป็น unparseable.

`step_success_rate = success / (success + error)`. unparseable แสดงแยกและไม่รวมเป็น failure ในตัวหาร. `step_total` แสดงทุก tool_call row. error ที่อยู่ซ้อนใน MCP `result` ไม่เปลี่ยน success ตามสูตรระดับบนสุด แต่รายงานแยกเป็น `partial_failure_count` พร้อม session, step และ tool. `investigate_ioc` ที่มี `llm_analysis.error` หรือ `sources.*.error` แสดงอีกแถวเป็นข้อมูลประกอบ และไม่รวมกับ partial_failure_count.

Flow B ยังคงนับ `audit_log` rows ที่ `action_type='tool_call'` โดย status `success` เทียบกับจำนวน tool_call rows เช่นสคริปต์เดิม.

## ชุดข้อมูลและช่วงเวลา

- As-recorded: 4 sessions ที่สร้างระหว่าง `2026-08-30T10:42:35Z` และ `2026-09-04T11:36:31Z`; metrics CSV เดิมอยู่ใน `evidence/operational_metrics_2026-09-27/`: `2320b6ac573d`, `ab2cb362c774`, `41fa383a6d03`, `b0c0c527cdbb`.
- Recomputed จากผลเต็มใน metadata: ใช้ session IDs เดียวกัน; เป็นการคำนวณซ้ำ ไม่ใช่การรัน playbook ใหม่.
- Flow C rerun: IDs ใน `scripts/adhoc/flow_c_rerun_session_ids.json` (`cc587d2786b6`, `e83135100307`, `8898632cbf7a`, `ee5744705850`, `b1afd5f64a38`, `7a5e681cf418`, `89fc75c9b0fe`, `4a2e030b1cee`) บวก `a643cd266adf` ที่ส่งด้วย `--extra-session-id`; IDs ทั้งหมดเป็น sessions วันที่ 2026-10-13 ตาม `agent_sessions`.
- ห้ามรวมชุด as-recorded กับ rerun เป็น metric เดียว.

## ผลแยกตามชุด

As-recorded จาก `agent_steps.tool_result`: success 15, error 0, unparseable 5, step_total 20; success rate เมื่อไม่นับ unparseable = 15/15.

อัตรา legacy ที่รายงานไว้ก่อนหน้าเป็น 15/20 = 75% เพราะ parser เดิมนับ parse failure เป็น false. ตัวเลข 75% นี้เป็นการอ่านตามสูตรเดิม; อย่านำไปรวมกับ rate ใหม่ที่ตัด unparseable ออกจากตัวหาร.

Recomputed โดยแทนห้าแถวที่ถูกตัดด้วยผลเต็มจาก `agent_sessions.metadata`: success 20, error 0, unparseable 0, step_total 20; success rate = 20/20.

Flow C rerun ที่ตรวจ DB: 73 tool_call rows, unparseable 0, wrapper 0. สคริปต์จะคำนวณ status และ partial failures จากแถวเหล่านี้ใหม่เมื่อเรียกใช้งาน.

การนับ Reject 3 ครั้งใน rerun เป็นการบังคับด้วย `--reject-every`; ไม่ใช่ Human Override Rate ของผู้ใช้จริง.

## ทำซ้ำ

เปิดฐานข้อมูลด้วย `mode=ro` เท่านั้น. คำสั่ง metrics ต่อไปนี้เขียน CSV report ในโฟลเดอร์นี้และไม่เขียนฐานข้อมูล.

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

สคริปต์ตรวจย้อนหลังพิมพ์เฉพาะ session, step, tool, flags, ความยาว serialized และผลเปรียบเทียบ prefix; ไม่พิมพ์ result payload.
