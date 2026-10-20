# SOCPOW Scope Ledger

**Last updated:** 17 Sep 2026

## Current session — AHP-derived production scoring amendment

This section is the current policy snapshot for the deadline deliverable.
Older sections below remain as audit history; where they describe the former
legacy tier constants, they are superseded by this section.

### Current production admission and multipliers

Production IOC scoring admits six explicitly approved sources. The multiplier
is source-specific and comes from the seven-source AHP model, not from the
legacy nominal tier constants and not from the exploratory CV coefficients.

| Source | Current multiplier | Production status | Current tier group |
|---|---:|---|---|
| `feodotracker` | `1.500000` | active scoring | high |
| `sslblacklist` | `0.878018` | active scoring; certificate-SHA1 feed only | medium |
| `spamhaus` | `0.695930` | active scoring | medium |
| `tor_exit_nodes` | `0.542480` | active scoring | medium |
| `c2_trackers` | `0.442818` | active scoring | medium |
| `threatfox` | `0.339610` | active scoring with timeout fallback | low |
| `virustotal` | `0.417347` | report-only; not admitted | AHP-only |

The authoritative derivation is
`docs/source_weight_ahp_derivation_2026-09-16.md`. It includes the 7x7
verification-rigor, specificity-of-scope, and maintenance/delisting matrices,
the evidence reference for every non-equal pairwise judgment, the priority
vectors, and the scale mapping. All three criteria have equal weight.

### Admission boundary and source handling

- `NON_API_SCORING_SOURCES` is the scoring admission allowlist in
  `src/scoring/intelligent_scoring.py`; it contains exactly the six active
  sources in the table above.
- `GROUP_B_EXCLUDE` remains the integration/coverage classification for
  supplemental API/query sources. It does not override the explicit scoring
  allowlist. ThreatFox is intentionally absent from Group B so its available
  result can contribute to scoring.
- VirusTotal remains in the AHP comparison for auditability, but remains
  report-only because local reliability telemetry is absent and the documented
  public limits are restrictive (`4 requests/minute`, `500 requests/day`).
- USOM remains report-only because it is a per-IOC query API. CIRCL is a
  permanent exclusion because Passive DNS requires partner authorization not
  available in this environment. SSLBL's deprecated IP feed is unavailable;
  only valid certificate-SHA1 observations can contribute.
- There is no unknown-source fallback multiplier. Unknown, untiered, stale, or
  unavailable sources do not become clean evidence.

### ThreatFox admission and timeout limitation

ThreatFox passed the separate admission gate, which is distinct from its lower
relative AHP weight:

- reliability telemetry: `720/720` successful rows across three windows;
- documented confirmed/vetted submission process and six-month expiry policy;
- latency limitation: `2/720` rows (`0.277778%`) exceeded the current 15-second
  production deadline, and both were URL records;
- the telemetry collector used a 30-second HTTP client timeout, so those two
  rows were successful in collection but would exceed the production deadline.

Production behavior for a ThreatFox timeout is deterministic: mark the source
`unavailable`, do not retry, do not block the pipeline, do not use stale cache
as a substitute, exclude it from the round's score/aggregate, and never
interpret it as clean. The behavior is covered by regression tests.

### AHP and validation status

The accepted AHP consistency ratios are:

| Criterion | CR | Gate |
|---|---:|---|
| Verification rigor | `0.024949` | pass (`<0.1`) |
| Specificity of scope | `0.061105` | pass (`<0.1`) |
| Maintenance/delisting policy | `0.017639` | pass (`<0.1`) |

The AHP values are documented judgments, not calibrated probabilities or
statistically fitted production weights. The earlier CV artifacts remain
`preliminary_signal_only`; the proxy holdout did not pass the independent
positive-overlap gates and was not used to fit or replace these values.

AHP replaces the source-specific legacy multipliers only. The separate
multi-source aggregation boosts remain unchanged in this session: the code
applies `base_score * 1.2` when at least three admitted sources are flagged and
`base_score * 1.15` when at least two are flagged. These boost factors are
legacy heuristics and are not derived by the AHP model.

### Session commits and files

The session incorporated the prior commits `8475992`, `651067a`, and
`8ffe764`, covering the exploratory CV artifact, SSLBL/USOM validation fixes,
and removal of the obsolete USOM bulk fallback. The current implementation
also updates the AHP derivation, source-tier policy, API-source and architecture
documentation, scoring code, evaluation-policy constants, and regression tests.
No evidence or pre-existing untracked evaluation artifact was overwritten or
included in this ledger update.

### Verification for this session

- Targeted regression suite: `51 passed, 1 warning, 4 subtests passed`.
- Python syntax compilation passed for the modified production and test files.
- `git diff --check` passed; remaining messages are Git's LF/CRLF conversion
  warnings only.
- No reliability window, full 894-record benchmark, or CV batch was rerun in
  this implementation session.

**Rule:** Section A ต้องปิดให้หมดก่อนเริ่ม Section B (backlog เดิม) เว้นแต่ Section A ข้อนั้น block อยู่จริงๆ

**Status:** ⬜ Not started | 🔍 Investigating | 📝 Fix drafted | ✅ Verified | 🚫 Blocked
**Evidence Tier:** T1 = Fully verified with evidence | T2 = Wired but not fully verified | T3 = Known limitation

---

### Future follow-up — page-level role guards for authenticated HTML routes

**Status:** `Not started` — explicitly outside the current authentication
workstream.

Several HTML pages currently have the new login/session guard but no matching
page-level role guard: `/settings`, `/` (`agent_chat.html`),
`/agent/playbooks` (`playbooks.html`), and `/agent/investigations`
(`agent_investigations.html`). Authenticated users without the required role
can therefore load a mostly non-functional page and encounter multiple
in-page `403 Insufficient permissions` responses. A future phase should decide
between enforcing page-level RBAC redirects and rendering a deliberate
insufficient-permissions state. This is a scope item only; it is not being
implemented in the current workstream.

## A. Advisor Comments (ตอบก่อนพรีเซนต์ครั้งหน้า)

| # | Comment | Status | Evidence Tier | Definition of Done | Next Action |
|---|---------|--------|----------------|---------------------|-------------|
| 1 | Severity levels: Malicious/Suspicious/Clean/Unknown vs Critical/High/Medium/Low | ✅ | T1 | ยืนยันว่า SOCPOW มี severity mapping อยู่แล้ว 3 ชั้น ไม่ใช่ gap ที่ต้องออกแบบใหม่: per-IOC (`src/utils/wazuh_severity.py:33-66`, `src/utils/helpers.py:63-95`) ใช้ score >=70 → CRITICAL, >=40 → HIGH, <40 → LOW และ verdict MALICIOUS→CRITICAL, SUSPICIOUS→HIGH, CLEAN/UNKNOWN→LOW; correlation (`src/agent/correlation.py:646-736`) รวม additive score แล้ว map >=60/40/20/10/else → critical/high/medium/low/info; external Wazuh alert (`src/utils/wazuh_severity.py:83-119`) map rule.level 14-15/12-13/7-11/0-6 → CRITICAL/HIGH/MEDIUM/LOW | ปิดแล้ว — ไม่ต้อง design ใหม่ เตรียมพูดประเด็น asymmetry ระหว่าง 3-tier (per-IOC) กับ 5-tier (correlation) เผื่ออาจารย์ถามต่อ |
| 2 | ทำไมต้องคูณ `base_score` ด้วย `1.3` และเลข `1.3` มาจากไหน | 🔍 | T3 | ตรวจพบจาก `src/scoring/intelligent_scoring.py:237` ว่า `1.3` ถูกใช้หลังคำนวณ weighted average เมื่อมี admitted Group-A sources flagged ตั้งแต่ 3 แหล่งขึ้นไป จึงเป็น 30% multi-source boost ไม่ใช่ base score; `git blame` ชี้กลับไปที่ commit `e12e768` แต่ commit message เป็นเพียง broad scoring improvement และยังไม่พบ derivation จากทฤษฎี, สถิติ, calibration, หรือเอกสารอ้างอิงใด ๆ ใน repository | ยังไม่ปิด: ตอบอาจารย์ว่า provenance ของ code พบแล้ว แต่เหตุผลเชิงทฤษฎี/สถิติของ `1.3` ยังไม่พบ; ห้ามอ้างว่าเป็น evidence-based factor และห้ามเปลี่ยน factor โดยไม่มี decision แยกพร้อมหลักฐาน/approval |
| 3 | Source ไหนน่าเชื่อถือที่สุด (ที่มาของ weight) | ✅ | T1 | ใช้ AHP (Saaty's pairwise comparison) บน 7 sources: `feodotracker`, `c2_trackers`, `spamhaus`, `tor_exit_nodes`, `sslblacklist`, `threatfox`, `virustotal`; เปรียบเทียบ verification rigor, specificity of scope และ maintenance/delisting policy โดยอ้างอิงเอกสารของแต่ละ feed ทุกคู่ที่ไม่เท่ากัน; priority vector รวมแบบ equal criteria แล้ว scale ให้ Feodo สูงสุด = `1.5`; VT ได้ multiplier สำหรับ audit เท่านั้นและยัง report-only | เตรียมอธิบายจาก `docs/source_weight_ahp_derivation_2026-09-16.md`: matrix → priority vector → CR → multiplier และแยก admission gate ออกจาก ranking |
| 4 | ช่องทางแจ้งเตือนผูกกับ severity ระดับไหน | ✅ | T1 | โค้ดจริงไม่มี Teams channel และไม่มี severity→channel mapping ใน SMTP/LINE: `NotificationManager.notify()` fan-out ทุก event ไปยัง channel ที่เปิดใช้งาน; mapping ตาม verdict มีเฉพาะ Gmail policy คือ `MALICIOUS→realtime`, `SUSPICIOUS→digest`, `CLEAN/UNKNOWN→none` (`src/integrations/notification_policy.py:22-32,61-88`) ส่วน `approval_required` และ `action_executed` เป็น realtime event ไม่ใช่ severity; `verdict_alert` ส่งให้ active Gmail ของ SOC Analyst Tier 1-2 + Team Lead, approval ส่งให้ Incident Responder, action ส่งตรงผู้อนุมัติ | ปิดคำถามด้าน code mapping แล้ว; ถ้าต้องการให้ Email/LINE/Teams มี severity routing แยก ต้องเป็น design/change ใหม่ ไม่ควรอ้างว่า implementation ปัจจุบันมี mapping ดังกล่าว |
| 5 | ความถี่แจ้งเตือน (IOC ใหม่เข้าทุกวัน) | ⬜ | - | policy เขียนชัด: real-time (Malicious) / digest (Suspicious) / none (Clean) + throttle/dedup rule | เช็คว่ามี throttle logic อยู่แล้วหรือต้องออกแบบใหม่ |
| 6 | Role definition + user manual ต่อ role + scope | ⬜ | - | ตาราง role × scope × ผู้เกี่ยวข้อง + manual สั้นต่อ role | เช็คว่ามี RBAC ในโค้ดหรือยัง (`rg "role" src/`) — ถ้าไม่มี ต้อง report เป็น gap ตรงๆ |
| 7 | ทฤษฎีการคำนวณ + trust source ต้องอธิบายได้ | ✅ | T1 | AHP derivation document อธิบาย Saaty's 1–9 scale, pairwise matrices, priority vectors, equal criterion aggregation, CR และการ scale เป็น multiplier; production scorer ใช้เฉพาะ `SOURCE_SCORING_MULTIPLIERS` ของ 6 active sources, ไม่มี unknown fallback, และไม่ตีความ AHP multiplier เป็น probability หรือ statistically-fitted coefficient | ใช้เอกสาร AHP เป็น handoff หลักในการตอบอาจารย์; ข้อ 2 เรื่อง base-score formula ยังเป็นงานแยกและยังไม่ปิด |
| 8 | Approval gate ที่ Detection Rule ทำไมต้องมี / SOC แก้ได้ไหม | ✅ | T1 | ยืนยัน 2 ประเด็น: (1) approval gate เป็น human gate เพื่อป้องกัน false positive หลุด production ตามเคส AlienVault ที่พบ และสร้าง accountability ผ่าน audit trail `approved_by/approved_at/deployed_by/deployed_at`; workflow validate → approve → deploy → export/ZIP implement ครบและบังคับผ่าน `_require_rule_export_approval()` (`src/web/routes/reports.py:107-118`) (2) SOC แก้เนื้อหา rule ได้แล้วจริงตั้งแต่ commit `f49aabc` ผ่าน `PUT /{analysis_id}/rules/{rule_type}` โดยใช้ `StrictStr`, เรียก `validate_rule()` ก่อน save และ hash-invalidation ใน `_get_rule_export_state()` (`src/web/routes/reports.py:87-104`) ทำงานอัตโนมัติเมื่อ content เปลี่ยน ยืนยันด้วย test แล้ว | ปิดแล้ว — เตรียมสไลด์ 2 ประเด็น (1) gate+audit trail (2) edit workflow ใหม่ที่ validate ก่อน save และ auto-invalidate approval เดิมเมื่อ content เปลี่ยน |

### A1. Severity mapping evidence (15 Sep 2026)

ระบบแยก severity เป็น 3 ระดับตามสิ่งที่กำลังประเมิน ไม่ใช่ scale เดียว:

| ระดับ | สิ่งที่ประเมิน | Mapping ที่มีอยู่แล้ว | Evidence |
|---|---|---|---|
| Per-IOC severity | IOC เดี่ยว / สัญญาณเดียว | `score >=70 → CRITICAL`, `>=40 → HIGH`, `<40 → LOW`; verdict `MALICIOUS→CRITICAL`, `SUSPICIOUS→HIGH`, `CLEAN/UNKNOWN→LOW` | `src/utils/wazuh_severity.py:33-66`; threshold ต้นทาง `src/utils/helpers.py:63-95` |
| Per-incident/correlation severity | เหตุการณ์ที่เชื่อมหลาย IOC/TTP | additive score: `>=60 critical`, `>=40 high`, `>=20 medium`, `>=10 low`, else `info`; แปลงต่อด้วย `correlation_to_wazuh_severity()` เป็น Wazuh 4-tier | `_assess_severity()` ที่ `src/agent/correlation.py:646-736`; conversion ที่ `src/utils/wazuh_severity.py:69-81` |
| External Wazuh alert ingestion | Wazuh `rule.level` 0-15 | `14-15 → CRITICAL`, `12-13 → HIGH`, `7-11 → MEDIUM`, `0-6 → LOW`; อิง significance cutoff `email_alert_level=12` | `src/utils/wazuh_severity.py:83-119` |

Correlation additive scoring แบบเต็ม:

- Overlap: ถ้ามี high-overlap อย่างน้อย 3 รายการ (`overlap.count >= 3`) ให้ `+30`; มิฉะนั้นถ้ามี overlap ให้ `+10 × min(number_of_overlaps, 5)`
- TTP tactic: `impact +25`, `credential-access +15`, `lateral-movement +15`, `command-and-control +15`
- Tactic coverage: ถ้ามีอย่างน้อย 4 tactics ให้ `+10`
- Finding verdict: malicious ตั้งแต่ 2 แหล่งขึ้นไป `+20`; 1 แหล่ง `+10`
- รวมคะแนนแล้ว map เป็น `>=60 critical`, `>=40 high`, `>=20 medium`, `>=10 low`, ต่ำกว่านั้น `info`

### A1.1. Correlation severity decision-table refactor (16 Sep 2026)

This entry supersedes the legacy additive-score description above for
correlation severity. The previous weights (`+30`, `+25`, `+15`, `+20`) and
score cutoffs (`60/40/20/10`) had no documented provenance and were removed
from `src/agent/correlation.py`.

| Severity | Deterministic rule | Evidence used |
|---|---|---|
| Critical | `any(o["count"] >= 3 for o in overlaps)` | Same IOC appears in at least 3 distinct findings/analyses |
| Critical | `malicious_count >= 2` and `{Impact, Command and Control}` is covered | At least 2 malicious findings plus both late kill-chain tactics |
| High | Any of `Impact`, `Credential Access`, `Lateral Movement`, `Command and Control` is present | High-risk MITRE tactic detected |
| High | `len(tactics_seen) >= 4` | At least 4 distinct canonical tactics detected |
| Medium | `len(overlaps) >= 1` or `malicious_count >= 1` | Correlation or malicious evidence exists, but no higher rule matched |
| Info | None of the rules above match | No escalation signal |

Implementation notes:

- Rules are evaluated in priority order: Critical, High, Medium, Info.
- `malicious_count` is deduplicated per finding; multiple qualifying fields in
  one finding count as one malicious source.
- Tactics are normalized with `normalize_tactic()` from
  `src/utils/mitre_kill_chain.py` before matching and coverage counting.
- Recommendations are generated independently from severity. Tactic-specific
  actions, malicious-confidence, coordinated-campaign, and medium-signal
  messages remain tied to their observable signals.
- Info-only results retain the fallback message: `No significant correlations found. Continue monitoring.` Medium/High/Critical results never use that fallback.
- Return contract is unchanged: `(severity, recommendations)`, with lowercase
  labels `critical`, `high`, `medium`, and `info`.

Verification: `python -m pytest tests/test_agent.py::TestCorrelationEngine -q --disable-warnings` → `45 passed, 0 failed`.

Downstream compatibility: the API response shape and
`correlation_to_wazuh_severity()` mapping remain unchanged. No corresponding
severity thresholds are externalized in `config.yaml` or
`config.yaml.example`.

### A1.2. Notification channel and severity routing evidence (17 Sep 2026)

ข้อสรุปที่ตรงกับโค้ดจริงคือ **severity ไม่ได้เป็นตัวเลือก channel สำหรับ SMTP/LINE**
โดยตรง แต่ระบบมีสองชั้นที่ต้องแยกกัน:

1. `NotificationManager` สร้าง channel จาก configuration และ fan-out event ไปยัง
   channel ที่เปิดใช้งานอยู่
2. Gmail เป็น channel แบบ per-user ที่มี policy แยกสำหรับ recipient,
   frequency, deduplication และ digest

| Event / severity | SMTP Email | LINE | Gmail | ผู้รับ/พฤติกรรมที่ยืนยันจากโค้ด |
|---|---|---|---|---|
| `verdict_alert` + `MALICIOUS` | ส่งถ้าเปิด channel | ส่งถ้าเปิด channel | realtime | Gmail route ไป active users ที่มี linked Gmail ใน role `SOC Analyst Tier 1-2` และ `Team Lead` |
| `verdict_alert` + `SUSPICIOUS` | ส่งถ้าเปิด channel | ส่งถ้าเปิด channel | digest | Gmail queue ต่อ user; digest loop ส่งรวมทุก 15 นาที |
| `verdict_alert` + `CLEAN`/`UNKNOWN` | ส่งถ้า caller ส่ง event เข้ามา | ส่งถ้า caller ส่ง event เข้ามา | ไม่ส่ง | Gmail policy คืน `none`; SMTP/LINE ไม่มี severity suppression ใน `notify()` |
| `approval_required` | ส่งถ้าเปิด channel | ส่งถ้าเปิด channel | realtime | Gmail ส่งเฉพาะ active linked Gmail ของ `Incident Responder` |
| `action_executed` | ส่งถ้าเปิด channel | ส่งถ้าเปิด channel | realtime | Gmail ส่งตรง user ID ใน `approved_by`; ไม่มี role broadcast |
| Teams | ไม่มี implementation | — | — | พบเพียง backlog reference; ไม่มี `TeamsChannel`, webhook หรือ Teams config key ใน production code |

#### Initialization and legacy channel fan-out

- `NotificationManager` อ่าน `config['notifications']`; ถ้า `enabled` ไม่เป็น
  `True` จะไม่สร้าง channel และ `notify()` จะ no-op:
  `src/integrations/notifications.py:139-158`
- SMTP ถูกเพิ่มเมื่อ `notifications.email.enabled` เป็นจริง และใช้
  `EmailChannel`: `src/integrations/notifications.py:40-84,160-163`
- LINE ถูกเพิ่มเมื่อ `notifications.line.enabled` เป็นจริง และใช้
  `LineChannel`: `src/integrations/notifications.py:87-133,164-166`
- Gmail ถูกเปิดโดย default เมื่อ notification system เปิดอยู่ เว้นแต่ตั้ง
  `gmail.enabled: false`: `src/integrations/notifications.py:168-181`
- `notify()` format subject/message แล้วเรียกทุก channel ใน `self.channels`
  โดยไม่ตรวจ verdict/severity ก่อนส่ง: `src/integrations/notifications.py:183-230`
  ดังนั้น SMTP/LINE เป็น **event fan-out** ไม่ใช่ severity-aware routing

ค่าตัวอย่างใน config ยืนยันว่า SMTP/LINE เป็น legacy static channels และ Gmail
เป็น per-user channel: `config.yaml.example:165-185`

#### Gmail policy flow

- `FREQUENCY_MAP` กำหนด `MALICIOUS→realtime`, `SUSPICIOUS→digest`,
  `CLEAN/UNKNOWN→none`; `approval_required` และ `action_executed` เป็น
  realtime: `src/integrations/notification_policy.py:22-32`
- `EVENT_ROLE_MAP` กำหนด `verdict_alert` ไป SOC Analyst Tier 1-2 + Team Lead
  และ `approval_required` ไป Incident Responder:
  `src/integrations/notification_policy.py:17-20`
- `action_executed` ไม่ใช้ role map แต่ resolve จาก `approved_by` และต้องเป็น
  active user: `src/integrations/notification_policy.py:70-88`
- `NotificationManager._notify_gmail()` หยุดทันทีเมื่อ frequency เป็น `none`,
  ทำ dedup ก่อน และ queue เฉพาะ digest:
  `src/integrations/notifications.py:232-300`
- dedup key ประกอบด้วย event, verdict, normalized IOC และ recipient; window
  5 นาที: `src/integrations/notification_policy.py:31,91-95` และ
  `src/integrations/notification_policy.py:143-183`
- SUSPICIOUS digest ถูกส่งรวมต่อ user โดย `send_pending_digests()` และ loop
  ทำงานทุก 15 นาที: `src/integrations/notifications.py:302-325`,
  `src/integrations/notification_digest.py:7-24`

#### Notification producers and important boundary

- Direct Flow A ของ `IOCInvestigator` ส่ง `verdict_alert` หลังคำนวณ verdict:
  `src/tools/ioc_investigator.py:253-281`
- Direct Flow A ของ `MalwareAnalyzer` ส่ง `verdict_alert` ผ่าน
  `_notify_verdict()`: `src/tools/malware_analyzer.py:128-149`
- Agent Loop ส่ง `verdict_alert` เฉพาะเมื่อ verdict อยู่ใน
  `notification_manager.create_on_verdict` ซึ่ง default config คือ
  `MALICIOUS` และ `SUSPICIOUS`: `src/agent/agent_loop.py:627-640`,
  `config.yaml.example:165-170`
- อย่างไรก็ตาม Direct Flow A เรียก `notify()` โดยตรงโดยไม่ตรวจ
  `create_on_verdict`; เมื่อ SMTP/LINE เปิดอยู่จึงควรถือว่า legacy channels
  อาจได้รับทุก `verdict_alert` ที่ Direct Flow A emit รวมถึง CLEAN/UNKNOWN
  ขณะที่ Gmail ยังคง suppress ตาม `FREQUENCY_MAP`
- Approval checkpoint และ approved action ใน Playbook emit
  `approval_required`/`action_executed`: `src/agent/playbook_engine.py:1248-1276`
  และ `1490-1511`
- Application wiring สร้าง NotificationManager แล้ว inject เข้า
  IOCInvestigator, MalwareAnalyzer และ AgentLoop:
  `src/web/app.py:290-318`

#### Verification

`tests/test_notification_routing_phase5.py` ยืนยัน role routing, Gmail
frequency, 5-minute dedup, 15-minute digest, SMTP/LINE parallel fan-out,
unlinked-recipient safety และ Direct Flow A triggers ที่
`tests/test_notification_routing_phase5.py:109-310`.

ดังนั้น row นี้ปิดได้ในระดับ **T1 สำหรับ behavior ที่มีอยู่จริง** แต่ยังไม่ใช่
ข้อสรุปว่า SMTP/LINE มี severity routing แบบเดียวกับ Gmail และ Teams ยังเป็น
backlog/design gap ไม่ใช่ implemented channel.

### A2. Detection rule edit endpoint (15 Sep 2026)

Commit: `f49aabc` (`feat: allow SOC to edit detection rules`)

| ไฟล์ | สิ่งที่เพิ่ม/ยืนยัน | Evidence |
|---|---|---|
| `src/web/analysis_manager.py` | `update_detection_rule()` ทำ read-modify-write ภายใต้ `self._lock` เดียวกับ `complete_job()`, serialize result ทั้งก้อนกลับ DB และคืน `False` โดยไม่ throw เมื่อไม่พบ job, parse result ไม่ได้, ไม่มี `detection_rules` หรือไม่มี `rule_type` | `src/web/analysis_manager.py:81-128` |
| `src/web/routes/reports.py` | เพิ่ม `PUT /{analysis_id}/rules/{rule_type}`; `RuleContentUpdateRequest` บังคับ `content: StrictStr`; validate ก่อน save; invalid ได้ 422; ไม่มี logic invalidate แยก เพราะ content hash ใน `_get_rule_export_state()` reset approval เป็น `pending_export` อัตโนมัติ | `src/web/routes/reports.py:54`, `:87-104`, `:264-301` |
| `tests/test_rule_export.py` | ครอบคลุม edit สำเร็จและ invalidate approval, field อื่นไม่หาย, persistence ข้าม `AnalysisManager` instance, invalid syntax, rule type ไม่มีจริง, list content ถูก reject ที่ schema, และ job ที่ไม่มี `detection_rules` คืน `False` | `tests/test_rule_export.py:195-288`; ผลรัน `57 passed` |

Known limitation: lock เป็นระดับ `AnalysisManager` ทั้งก้อน ไม่ใช่ต่อ job
หรือ `analysis_id`; SOC หลายคนที่แก้คนละ analysis พร้อมกันจะรอคิวบน
`self._lock` แต่ไม่ error อาจช้าลงตามจำนวน concurrent edits ยอมรับได้ใน
สเกลปัจจุบัน และไม่อยู่ใน scope ที่ต้องแก้รอบนี้

### A3. Source trust and weight derivation (16 Sep 2026)

คำตอบที่ล็อกสำหรับคำถามว่า source ไหนน่าเชื่อถือที่สุด ไม่ใช่การอ้างว่า
source ใดมีชื่อเสียงที่สุดหรือใช้ API ได้ง่ายที่สุด แต่ใช้ AHP เพื่อจัดอันดับ
เชิงเปรียบเทียบจาก evidence ที่ตรวจสอบได้:

| ขั้น | วิธีตัดสิน | ผลที่ได้ |
|---|---|---|
| 1 | กำหนด source universe 7 ตัว รวม VirusTotal เพื่อให้เปรียบเทียบและ audit ได้ | FeodoTracker, C2 Trackers, Spamhaus, Tor Exit Nodes, SSLBL, ThreatFox, VirusTotal |
| 2 | กำหนด 3 criteria ที่มีเหตุผลเชิง operational/content แยกจาก availability | verification rigor, specificity of scope, maintenance/delisting policy |
| 3 | ให้ pairwise value ด้วย Saaty scale `1–9`; ทุกคู่ที่ไม่ใช่ 1 มี source reference ใน derivation doc | ได้ 3 matrices ขนาด `7×7` |
| 4 | คำนวณ priority vector และตรวจ Consistency Ratio | CR = `0.024949`, `0.061105`, `0.017639`; ผ่านทุก matrix (`<0.1`) |
| 5 | เฉลี่ย priority vector ของ 3 criteria ด้วยน้ำหนักเท่ากัน `1/3` | FeodoTracker มี priority สูงสุด `0.3114486393` |
| 6 | scale ด้วย `1.5 / 0.3114486393` เพื่อรักษาเพดานเดิม | ได้ multiplier ราย source ที่อยู่ใน current production table |

ผลลัพธ์นี้เป็น **AHP-derived judgment** ไม่ใช่ trained model coefficient,
calibrated probability หรือหลักฐานว่า source ที่ได้คะแนนต่ำเป็น source ที่
ผิดพลาดเสมอ การ admit เข้า production เป็น gate แยกจากอันดับ AHP: ThreatFox
ผ่าน evidence/availability gate จึง active ได้ แม้มี multiplier ต่ำสุด ส่วน
VirusTotal มี AHP candidate multiplier แต่ยังไม่ผ่าน local telemetry และ
availability gate จึงคง report-only.

Evidence และตัวเลขเต็มอยู่ใน
`docs/source_weight_ahp_derivation_2026-09-16.md`; policy ที่ sync แล้วอยู่ใน
`docs/source_tier_policy_decision_2026-09-16.md`, `docs/API_SOURCES.md`,
และ `docs/ARCHITECTURE.md`.

### A7. Scoring theory and source trust explanation (16 Sep 2026)

สูตรที่ตอบคำถาม trust/weight ใน session นี้มีสองชั้น และต้องแยกจาก legacy
aggregation boost ให้ชัดเจน:

1. **Source contribution:** ถ้า source อยู่ใน `NON_API_SCORING_SOURCES`, มีผล
   สำเร็จ/flagged และไม่ใช่ `unavailable`, คะแนน source จะถูกคูณด้วย
   `SOURCE_SCORING_MULTIPLIERS[source]`; source อื่นเป็น report-only และไม่มี
   unknown fallback multiplier.
2. **AHP derivation:** multiplier มาจาก priority vector ที่รวม 3 criteria
   ด้วยน้ำหนักเท่ากันและ scale ตาม Feodo = `1.5`; ไม่ได้ fit จาก label ใน
   exploratory CV.
3. **Legacy multi-source boost:** หลัง weighted average โค้ดยังคูณ `1.3`
   เมื่อมีอย่างน้อย 3 admitted sources flagged และคูณ `1.15` เมื่อมีอย่างน้อย
   2 แหล่ง ค่าเหล่านี้เป็น heuristic เดิม ไม่มี derivation ที่พบใน repository
   และไม่ได้มาจาก AHP.
4. **Availability separation:** ThreatFox timeout ที่เกิน 15 วินาทีเป็น
   `unavailable`, ไม่ retry, ไม่ block, ไม่ใช้ stale cache แทน และถูกตัดจาก
   score/aggregate; จึงไม่ถูกนับเป็น clean.

Advisor Comment #2 ยังไม่ปิด แม้จะพบ provenance ของ code แล้ว เพราะยังตอบไม่ได้
ว่าเหตุใดจึงเลือก `1.3` ในเชิงทฤษฎีหรือสถิติ ผลที่ยืนยันได้ตอนนี้คือ `1.3`
เป็น legacy heuristic ที่ไม่มีที่มาที่ตรวจสอบได้ ไม่ใช่ตัวเลขที่พิสูจน์แล้วหรือ
AHP-derived factor. หากจะเปลี่ยน ต้องเปิด decision แยกและเพิ่มหลักฐาน/approval
ไม่ควรเปลี่ยนโดยอัตโนมัติจากงาน AHP.

### DGA and domain-age scoring provenance (16 Sep 2026)

This is recorded as a system-provenance finding, not as a newly designed
scoring policy. The current implementation inherited these values from the
initial v2.0 implementation in commit `e12e768`:

| Signal | Current calculation | Current numeric value | Provenance/status |
|---|---|---:|---|
| DGA confidence | Sum of heuristic components: normalized Shannon entropy (maximum 25), consonant ratio (15), common-bigram scarcity (20), common-trigram scarcity (10), digit ratio (10), dictionary-word coverage (15), and unusual SLD length (5) | Maximum `100`; `confidence >= 50` means `is_dga=true` for detection/metadata | Implemented in `src/utils/dga_detector.py:402-479, 583`; retained as pattern detection and analyst context; confidence/component weights remain heuristic |
| DGA enrichment | If `is_dga=true`, retain the finding in enrichment and recommendations | No numeric score contribution (`0`) | Numeric bonus removed by commit `bb16056`; DGA metadata remains available to analysts |
| Newly registered domain | WHOIS `creation_date` is parsed, then `age_days = (now_UTC - creation_date).days`; set `is_newly_registered=true` when age is below the cutoff | `<30` days for detection/metadata; no numeric score contribution (`0`) | Age logic in `src/utils/domain_age_checker.py:207-264`; numeric bonus removed by commit `bb16056`; domain-age metadata remains available to analysts |
| Domain-age risk labels | Compare integer `age_days` with fixed thresholds | `<7` critical, `<30` high, `<90` medium, `<365` low, otherwise none | Implemented in `src/utils/domain_age_checker.py:47-67`; operational labels, not a validated probability model |

**Why the system retains these signals:** newly registered and algorithmically
generated domains remain useful contextual/pattern-detection signals for
analysts. They are retained in enrichment and recommendations, but no longer
contribute numeric points to `threat_score` or determine the verdict.

**WHOIS behavior:** `check_domain_age()` first tries `python-whois`, then falls
back to raw socket WHOIS with a default 10-second timeout. It accepts several
date formats, uses the first date when a registrar returns a list, normalizes
naive timestamps to UTC, caches results in memory, and returns
`is_newly_registered=false` when no creation date is available. The age is
therefore an integer full-day difference, not an exact elapsed-hour measure.

**Pipeline path:** the main IOC investigation calls
`IntelligentScoring.calculate_ioc_score(intel_results)` for the numeric score.
Domain enrichment is collected separately and returned for analyst-facing
metadata/recommendations; it does not alter `threat_score` or the verdict
(`src/tools/ioc_investigator.py`).

**Decision status:** the former `+20` and `+30` magnitudes had no defensible
statistical justification from the available data, so both numeric bonuses
were removed. The detection cutoffs remain implementation heuristics and are
not presented as calibrated probabilities. This is separate
from Advisor Comment #2: that comment about the multi-source `base_score * 1.3`
factor also remains open (`🔍`).

### Historical domain-age bonus (+20) empirical calibration attempt (superseded)

**Historical motivation.** This investigation attempted to calibrate the former
domain-age bonus `+20` using observed labelled data. The results are retained
for provenance only; they do not describe current production scoring.

#### Test 1 — Static benchmark (422 domain records)

The benchmark contained `240` `MALICIOUS` and `182` `CLEAN` domain records.
`381/422` WHOIS lookups succeeded; `41` records were excluded from analysis with
error type `NoWhoisCreationDate`.

| WHOIS age group | MALICIOUS | CLEAN | Total | Malicious rate |
|---|---:|---:|---:|---:|
| Newly registered (`<30d`) | 5 | 0 | 5 | `5/5 = 1.0` (100%) |
| `>=30d` | 194 | 182 | 376 | `194/376 = 0.5159574468085106` (51.6%) |

The standard two-sided Fisher exact test returned `p=0.06210071192843707`
(approximately `0.062`), which was not significant at `alpha=0.05`. The
zero-cell table and the very small newly-registered group make that test weakly
powered. The one-sided exact binomial test against the mature-domain baseline
rate returned `p=0.0366`, significant at `alpha=0.05`, and supports the intended
direction. However, the newly-registered sample size was only `n=5`, so it is
not sufficient to derive a stable point value.

#### Test 2 — Live NRD feed sample (250 domains, `smet_nrd` + `hagezi_nrd`)

The run drew `250` domains from the current live newly registered domain feeds.
Live NRD membership was used only to define the newly-registered sample (without
WHOIS); it was not used as the label. Labels were produced by the existing verdict
pipeline through an adhoc wrapper that removed domain-age enrichment, the `+20`
bonus, and `is_newly_registered` from verdict computation. NRD-feed hits were also
excluded from the label sources. The label used only the DGA detector plus
ThreatFox/C2-tracker evidence, preserving the existing verdict logic while
avoiding circular reasoning.

The combined analysis had `5/255` newly-registered domains labelled malicious
(`5/255 = 0.0196078431372549`, 1.96%), compared with the `194/376` mature-domain
baseline (`0.5159574468085106`, 51.6%). The two-sided Fisher exact test was
significant, `p=3.5907886347686414e-48`, but in the opposite direction. The
one-sided exact binomial test for the required alternative
(`newly registered` malicious rate greater than baseline) returned `p=1.0`, so
there was no significance in the direction needed to support a positive bonus.

This result does **not** mean that newly registered domains are genuinely safer.
It reflects label-starvation bias: ThreatFox and C2-tracker feeds tend to flag a
domain after it has been used in a real attack and reported. Freshly registered
domains, including some only a few days old, have often not had time to enter
those feeds, so the two-source automated pipeline systematically returns
`CLEAN`. These labels are therefore not verified ground truth. This is a known
limitation of the rapid, two-source automated labelling approach used within one
day, not evidence that the `+20` signal is wrong.

#### Combined conclusion

- The `<30 days` cutoff remains consistent with the cited industry practice in
  the preceding section: Netskope uses a 30-day window and Palo Alto Networks
  Unit 42 reports a 32-day early-life window. Those references support the
  cutoff and signal direction, not SOCPOW's exact numeric bonus.
- The static-benchmark test gave the correct direction and a significant
  one-sided result (`p=0.0366`), but `n=5` is too small for a stable point-scale
  derivation.
- The live-feed expansion reached `255` newly-registered observations, but its
  automated labels exposed label-starvation bias. The result is not evidence
  that `+20` is incorrect; it is evidence that this labelling design cannot
  calibrate the weight reliably.
- At the time, no change to the `+20` value was proposed in code. The live
  calibration output recorded no defensible replacement point value. This
  historical proposal was superseded by the final decision in commit
  `bb16056`, which removed the numeric domain-age/DGA bonuses entirely.
- The direction of the signal (`newly registered = riskier`) remains supported
  by the cited external literature and by Static Test 1. The unresolved item is
  the exact numeric weight, not the intended direction.

**Reproducibility files.** The investigation used
`scripts/adhoc/domain_age_calibration.py`,
`scripts/adhoc/domain_age_calibration_input.json`,
`scripts/adhoc/domain_age_calibration_results.jsonl`,
`scripts/adhoc/domain_age_calibration_summary.json`,
`scripts/adhoc/nrd_live_sample.json`,
`scripts/adhoc/nrd_live_labeled.jsonl`, and
`scripts/adhoc/nrd_live_calibration_summary.json`. These files are gitignored
according to the repository's existing adhoc convention.

### External references for DGA/domain-age feature choice (16 Sep 2026)

The following external literature and industry references support the direction
of the signals and the choice of features/cutoff. They do not replace the
implementation provenance recorded in the preceding section.

#### Newly registered domain cutoff

| Reference | Relevant finding | Relationship to SOCPOW |
|---|---|---|
| Netskope Community, [Best Practices - Newly Registered Domains (NRDs)](https://community.netskope.com/real-time-protection-key-policies-72/best-practices-newly-registered-domains-ndrs-7668) | Uses a default 30-day classification window for newly registered domains. | Supports SOCPOW's `<30 days` cutoff as being consistent with an industry practice. |
| Palo Alto Networks Unit 42, [Newly Registered Domains: Malicious Abuse by Bad Actors](https://unit42.paloaltonetworks.com/newly-registered-domains-malicious-abuse-by-bad-actors/) | Reports that more than 70% of observed NRDs were malicious, suspicious, or NSFW. | Supports the direction that newly registered domains are a higher-risk contextual signal, not that every NRD is malicious. |
| Palo Alto Networks Unit 42, [Detecting Emerging Network Threats From Newly Observed Domains](https://unit42.paloaltonetworks.com/malicious-newly-observed-domains/) | Uses a 32-day NRD window; reports that 37.11% of suspicious newly observed domains were confirmed malicious within the following 30 days, and identifies the first 32 days as the optimal timeframe for detecting malicious NRDs. | Supports a short early-life window near SOCPOW's 30 days; the 32-day finding is not a direct derivation of SOCPOW's exact cutoff. |

These references support the direction of the signal (`newly registered` means
contextually riskier) and indicate that a 30-day cutoff is close to industry
practice. They do **not** establish a numeric SOCPOW score contribution; the
former `+20` domain-age bonus is no longer used.

#### DGA feature selection

| Reference | Relevant finding | Relationship to SOCPOW |
|---|---|---|
| Atlantis Press, [A Detection Scheme for DGA Domain Names Based on SVM](https://www.atlantis-press.com/article/25894313.pdf) | An SVM-based detector uses domain length, Shannon entropy, vowel ratio, consecutive-consonant ratio, and digit ratio; it reports TPR above 87% and precision above 88%. | Supports SOCPOW's use of length, entropy, consonant/vowel composition, and digit ratio as plausible DGA features. The reported metrics belong to that study's dataset/model, not SOCPOW. |
| Splunk, [Machine Learning in Security: Deep Learning Based DGA Detection with a Pre-trained Model](https://www.splunk.com/en_us/blog/security/machine-learning-in-security-deep-learning-based-dga-detection-with-a-pre-trained-model.html) | Describes entropy, vowel/consonant/digit ratios, and n-gram similarity to dictionary words as standard features that correlate with DGA labels. | Supports SOCPOW's feature direction, including dictionary coverage and n-gram/bigram/trigram signals. |
| Exp0se DGA Detector, referenced by [Gravity Falls: A Comparative Analysis of DGA Detection Methods for Mobile Device Spearphishing](https://arxiv.org/pdf/2603.03270) | A traditional heuristic/string-analysis detector uses entropy, consonant count, and string-length thresholds. | Supports the general heuristic design pattern used by SOCPOW; it is not evidence that SOCPOW's exact points or thresholds are optimal. |

These references support the direction that entropy, consonant/vowel ratio,
digit ratio, length, dictionary coverage, and n-gram features can help separate
DGA-like domains from ordinary domains. They **do not** validate SOCPOW's exact
component weights (`25/15/20/10/10/15/5`) or confidence threshold (`50`). The
former `+30` DGA bonus was an implementation-specific legacy heuristic and is
no longer used for numeric scoring.

#### Explicit evidence boundary

The references validate **feature choice and signal direction**, not the exact
numeric scoring policy. In particular:

- `newly registered = riskier` is supported directionally, and the 30-day
  cutoff is close to documented industry windows (30 and 32 days).
- entropy, consonant/vowel ratio, digit ratio, length, dictionary coverage,
  and n-gram features are supported as literature/industry feature choices for
  DGA detection.
- SOCPOW's exact detector component weights `25/15/20/10/10/15/5` and
  confidence threshold `50` remain unvalidated legacy heuristics. The former
  DGA `+30` and domain-age `+20` numeric bonuses were removed and are not
  current scoring factors. No cited reference directly proves those historical
  numbers.

This distinction must be preserved in the advisor handoff: external references
support the rationale for the signals, while independent labelled validation
and calibration are still required before presenting SOCPOW's exact numbers as
evidence-based or statistically validated.

### Turkish-language code audit (16 Sep 2026)

**วัตถุประสงค์:** ตรวจว่ามีข้อความภาษาตุรกีที่ปะปนใน source code จาก code เดิม
หรือไม่ เพื่อวางแผนทำให้ comments, docstrings และข้อความประกอบโค้ดเป็นภาษา
อังกฤษสม่ำเสมอสำหรับการ review, maintenance และการตอบอาจารย์

**วิธีตรวจ:** ใช้ `rg` scan ใน `src/`, `scripts/`, `tests/`, `docs/`,
`templates/`, `README.md` และ `config.yaml.example` โดยค้นหาอักขระ Turkish
ที่มี diacritic (`ç ğ ı ö ş ü` และตัวพิมพ์ใหญ่) และคำ Turkish ที่พบบ่อย;
ไม่นับ `evidence/`, `evidence_raw/`, JSON/JSONL และฐานข้อมูลเป็น source code
สำหรับงานนี้

**ผลการตรวจ source code:** character scan รอบแรกพบ `75` matching lines ใน `src/`
จำนวน `18` ไฟล์จากอักขระ Turkish ที่มี diacritic. จากนั้น supplemental scan
สำหรับคำ Turkish แบบ ASCII/คำผสม Turkish-English พบข้อความเพิ่มเติมใน analyzer,
adaptive scoring และ kill-chain utility รวมเป็น source files ที่ต้อง cleanup
ทั้งหมด `21` ไฟล์. จุดที่พบทั้งหมดเป็น module/class docstring, function
docstring, documentation comment หรือ version note ไม่ใช่ runtime decision
logic และไม่พบ user-facing runtime string ที่ต้องเปลี่ยนความหมาย.

| กลุ่ม | ไฟล์ที่พบ | ตัวอย่างจุดที่ต้องเปลี่ยนเป็น English |
|---|---|---|
| Analyzer modules | `src/analyzers/apk_analyzer.py`, `capability_analyzer.py`, `elf_analyzer.py`, `file_type_router.py`, `firmware_analyzer.py`, `macho_analyzer.py`, `obfuscated_string_analyzer.py`, `office_analyzer.py`, `pdf_analyzer.py`, `script_analyzer.py`, `text_analyzer.py` | module/class docstrings และ comments เช่น `Kapsamlı`, `Dosya`, `Yüksek`, `Çıkarılan`, `Geçerli`, `kategorize` |
| Threat intelligence | `src/integrations/threat_intel.py` | `:556` docstring note `İyileştirildi - hata yönetimi`; ต้องเปลี่ยนเป็น English โดยไม่เปลี่ยน API behavior |
| Scoring | `src/scoring/intelligent_scoring.py`, `src/scoring/tool_based_scoring.py` | `intelligent_scoring.py:475,491,529` และ tool-weight comments/docstrings เช่น `ağırlık`, `yüksek`; ต้องไม่เปลี่ยนสูตรหรือ multiplier ระหว่าง language cleanup |
| Reporting/tools | `src/reporting/tool_output_formatter.py`, `src/tools/email_analyzer.py`, `src/tools/external_tool_runner.py` | formatter/analyzer/runner docstrings และ comments ที่เป็น `Türkçe` |
| Utility | `src/utils/ioc_extractor.py` | `:172, :320, :323, :326` เช่น `İyileştirildi`, `Sondaki`, `Başındaki`, `Geçerli` |

**สถานะ:** `[x]` technical-debt cleanup เสร็จแล้วใน session ปัจจุบัน. แปลข้อความ
ใน source code ที่ตรวจพบเป็น English โดยแก้เฉพาะ comments/docstrings/version
notes; ไม่แก้ identifier, constant, formula, threshold, control flow หรือ
scoring behavior. รายการในตารางด้านบนคือจุดที่พบจาก initial character scan;
มี supplemental cleanup เพิ่มเติมใน `src/analyzers/pe_analyzer.py`,
`src/scoring/adaptive_scoring.py` และ `src/utils/mitre_kill_chain.py` ซึ่งเป็น
ข้อความ Turkish แบบไม่มี diacritic.

**Verification evidence (16 Sep 2026):**

- `rg -n "[çğıöşüÇĞİÖŞÜ]" src` ให้ผล `NO_TURKISH_DIACRITICS_IN_SRC`.
- supplemental Turkish-stem scan ใน `src/**/*.py` ให้ผล
  `NO_TURKISH_STEMS_IN_SRC`.
- `python -m compileall -q src` ผ่านสำหรับ source tree ที่แก้ (`PY_COMPILEALL_PASS`).
- targeted regression tests ผ่าน: `pytest -q tests/test_scoring_confidence.py
  tests/test_threat_intel_source_accounting.py tests/test_threat_intel_cache_fallback.py
  tests/test_fit_source_weights_policy.py` → `39 passed`, 1 existing
  `PytestCacheWarning` เรื่อง cache path.
- `git diff --check` ผ่านสำหรับไฟล์ที่แก้.
- diff ตรวจแล้วเป็น documentation-language-only ใน source files; Advisor
  Comment #2 เรื่องที่มาของ `base_score * 1.3` ยังคงเป็น `🔍` และไม่ได้ถูกปิด
  หรือเปลี่ยนแปลงจากงานแปลภาษา.

**Definition of done:** แปล comments/docstrings เป็น English, ตรวจแยก
user-facing/runtime strings, เพิ่ม regression check ว่าไม่มี Turkish text ใน
ไฟล์ที่อยู่ใน production review scope และยืนยันว่า diff ไม่เปลี่ยน logic,
formula, threshold หรือ scoring result. งานนี้เป็น code/documentation hygiene
แยกจากการหาที่มาของ factor `1.3` และไม่สามารถใช้แทน theoretical/statistical
derivation ของ `1.3` ได้.

---

## B. Backlog (ห้ามแทรกก่อน Section A เสร็จ เว้นแต่ blocked)

| Item | Status | Notes |
|------|--------|-------|
| FuzzyHashAnalyzer ssdeep/tlsh fix | ⬜ | scoped ~15-20 lines, รอตัดสินใจ investigate vs direct fix |
| DGA `_extract_sld()` subdomain gap | 🔍 | รอ rg เพิ่มก่อนเขียน fix |
| RAG auto-seeding on startup | ⬜ | ยังไม่ยืนยันว่า `kb.seed()` รันตอน uvicorn startup |
| Email-level RAG references (Flow B) | 📝 | prompt ส่งให้ Codex แล้ว รอผล |
| HTML report 404 (3 playbooks) | ⬜ | pre-existing gap, ทราบ root cause แล้ว |
| Detection Rule Export remaining gaps | ✅ | ผิด — investigate แล้วพบว่า validate/approve/deploy/download/zip ครบใน `src/web/routes/reports.py` (ดู Section A #8 และ A2) gap จริงมีแค่ edit content ซึ่งตอนนี้ implement แล้วที่ commit `f49aabc` เช่นกัน ปิดแถวนี้ |
| Teams notification | ⬜ | paused, prompt drafted |
| Test Case checklist (Excel) | ⬜ | not yet requested |
| UDP visibility in netstat_collect | ⬜ | low priority unless demo needs it |
| RAG coverage matrix | ⬜ | backlog |
| ATT&CK STIX/TAXII ingestion | ⬜ | backlog |

---

## C. Group A Eval (exploratory evidence; current policy is AHP above)

ส่วนนี้เป็นสถานะของการเก็บผล Group-A และ CV เชิงสำรวจ ไม่ใช่ source of truth
ของ production multiplier ปัจจุบัน ตัวเลข legacy tier และข้อความที่ระบุว่า
ยังรันไม่ครบด้านล่างเป็น execution snapshot ของช่วงก่อน AHP และต้องอ่านคู่กับ
current session section ด้านบนเท่านั้น

| Item | Status | Evidence Tier | Evidence / Current State | Next Action |
|------|--------|----------------|--------------------------|-------------|
| Dataset และ default limit | ✅ | T1 | `eval_benchmark.py` ใช้ `benchmark_iocs_v2.json` จำนวน 894 รายการ (`MALICIOUS=709`, `CLEAN=185`) และผล canonical JSONL มี 894 rows | ไม่ต้อง rerun สำหรับ current AHP policy |
| Resume และ graceful Ctrl+C | ✅ | T1 | `load_existing_results()` ข้าม malformed JSON พร้อม warning; loop flush ผลทีละ record และจับ `KeyboardInterrupt` ก่อนปิดไฟล์ | ใช้ `--resume` ต่อหลังหยุด/เครื่องกลับมา |
| Fit/score result path | ✅ | T1 | `scripts/eval/fit_source_weights.py` ใช้ `scripts/eval/eval_results_group_a_v2.jsonl`; exploratory artifact คือ `scripts/eval/fit_source_weights_results_6source.json` และสถานะ `preliminary_signal_only` | ห้ามนำ CV coefficient ไปแทน AHP multiplier โดยตรง |
| Group A eval execution | ✅ | T1 | Canonical result file ตรวจพบ 894 rows; exploratory six-source artifact ใช้ dataset 894 rows แต่ cache coverage/missingness จำกัดการตีความ | ไม่ต้อง rerun full benchmark ใน current session |
| แยก workflow ออกจาก `scripts/adhoc/` | ✅ | T1 | ย้าย `eval_benchmark.py`, `fit_source_weights.py` และ `group_b_exclusion_rationale.md` ไป `scripts/eval/`; เพิ่ม explicit unignore ที่ `.gitignore:99-100`; scratch files คงอยู่ใน `scripts/adhoc/` | ใช้ `scripts/eval/` สำหรับ repeatable evaluation/documentation; ไม่ย้าย `score_eval_results.py` |

### Group A files and evidence

- Dataset: `data/benchmark/benchmark_iocs_v2.json` — 894 records (`MALICIOUS=709`, `CLEAN=185`)
- Running script: `scripts/eval/eval_benchmark.py`
- Incremental results: `scripts/eval/eval_results_group_a_v2.jsonl`
- Analysis tools: `scripts/eval/fit_source_weights.py`, `scripts/adhoc/score_eval_results.py`
- Exploratory artifact: `scripts/eval/fit_source_weights_results_6source.json`
- These are local/generated evidence files; do not overwrite them or interpret
  their coefficients as the current production weights.

---

## D. Session handoff — ThreatFox verification, Group A/B scoring boundary, and evidence (historical record)

The D sections preserve dated investigation history. Their former tier
assignments, CV readiness statements, and proposed next steps are not the
current production policy; consult the current-session section at the top for
the authoritative AHP/admission state.

**Session date:** 14 Sep 2026

**Scope rule:** งานในส่วนนี้ไม่แตะ `src/mcp_servers/**`, `mcp_client.py`,
`src/web/websocket.py` หรือ `config.yaml` และยังไม่มี commit

### D1. ThreatFox configuration and live verification

- ตรวจ `config.yaml` แบบไม่พิมพ์ค่า secret: `api_keys.threatfox = True`,
  `api_keys.abusech = False`
- `check_threatfox()` ที่ `src/integrations/threat_intel.py:542` ใช้ key จาก
  `threatfox` ก่อน fallback ไป `abusech`; request อยู่ที่ `:550`
- `investigate_ioc_comprehensive()` เรียก ThreatFox แบบ unconditional ที่ `:954`
  ดังนั้นยังมี task สำหรับ IPv4, domain, URL และ hash ที่ส่งเข้า investigation
- Live direct-call sample จาก session เดียวกันตอบ HTTP 200 ครบ 5 รายการ:

| IOC type | IOC label | Latency | Result |
|---|---|---:|---|
| IPv4 | `8.8.8.8` | 905.5 ms | `Not listed` |
| Domain | `example.com` | 492.7 ms | `No exact match` |
| URL | `https://example.com/` | 644.9 ms | `Not listed` |
| MD5 | `44d88612fea8...` | 502.8 ms | `Not listed` |
| SHA256 | `0123456789ab...` | 487.4 ms | `Not listed` |

Summary: average **606.7 ms**, median **502.8 ms**, range **487.4-905.5 ms**;
ไม่พบ timeout, exception หรือ HTTP error ใน sample นี้ จึงคง ThreatFox ไว้
ใน Group A

### D2. Group B exclusion design and implementation

Group B ที่ถูก exclude จาก scoring/verdict มี 13 source:

```text
virustotal, abuseipdb, shodan, alienvault, greynoise, censys,
pulsedive, criminalip, ipqualityscore, phishtank, ip2proxy,
triage, threatzone
```

เหตุผลเป็น **dependency/source-path reliability gate** ไม่ใช่การตัดสินว่า
information content ของ source เหล่านี้เป็นเท็จ: auth gate, rate limit และ
timeout ที่ observe ได้ทำให้ไม่เหมาะกับ critical scoring path แต่ยังมีประโยชน์
เป็น supplemental evidence

| จุด | สถานะหลังแก้ | Evidence |
|---|---|---|
| Constant | ✅ | `src/integrations/threat_intel.py:24` — `GROUP_B_EXCLUDE` |
| Raw source retention | ✅ | `threat_intel.py:1096` ยังคงคืน `sources: results` ครบทุก source |
| Threat-intel aggregate | ✅ | `threat_intel.py:1074-1076` skip Group B ก่อนนับ flag/รวม score; `threat_score` aggregate จึงเป็น Group A |
| IOC weighted scoring | ✅ | `src/scoring/intelligent_scoring.py:131`, `:184` skip Group B ก่อน `_get_source_score`; `:213-215` ใช้ Group A flag count สำหรับ boost |
| Coverage transparency | ✅ | `intelligent_scoring.py:235-254` แยก `coverage.group_a` และ `coverage.group_b`; top-level historical fields mirror Group A ที่ `:299-300` |
| Verdict coverage | ✅ | `src/utils/helpers.py:63-85` ไม่ต้องแก้เพิ่ม เพราะ `determine_verdict()` อ่าน top-level coverage ที่ถูกตั้งเป็น Group A แล้ว |
| Informational attempted count | ✅ | `threat_intel.py:1091` `sources_checked` ยังนับทุก task ที่พยายามเรียก รวม Group B ตาม design |

### D3. Timeout finding

`safe_execute()` ที่ `threat_intel.py:1026-1029` ใช้ `asyncio.wait_for(coro,
timeout=15.0)` กับทุก task โดยรันผ่าน `gather()` ที่ `:1054` แบบ concurrent ดังนั้น
แต่ละ task มี deadline ของตัวเอง แต่ policy เป็นค่าเดียว global สำหรับทุก source
ไม่ใช่ per-source timeout

ตาม scope decision รอบนี้จึง **ยังไม่ลดเป็น 3 วินาทีและไม่ทำ per-source timeout**:
Group B ถูกกันออกจาก scoring แล้ว แต่ยัง best-effort และอาจกินเวลารอได้ถึง 15 วินาที
เพื่อไม่ขยาย scope โดยไม่จำเป็น

### D4. Test update and verification

ปรับเฉพาะ test files ที่อนุญาต:

- `tests/test_censys_scoring.py` — Censys assertion ย้ายไป `coverage['group_b']`
- `tests/test_scoring_confidence.py` — generic aggregation ใช้ synthetic source names,
  strict expected dict เพิ่ม `group_a/group_b`, missing-key tests ตรวจ Group B
- `tests/test_threat_intel_source_accounting.py` — hash accounting แยก Group A/B

Verification results:

| Check | Result | Interpretation |
|---|---:|---|
| `python -m py_compile` ของ test files | Pass | ไม่มี syntax error |
| Tests ที่แก้โดยตรง | **22 passed** | ทั้ง 15 design-change failures เดิมถูกอัปเดตแล้ว |
| Full `pytest -q` | Blocked at collection | `tests/test_remote_tools.py` import `paramiko` ไม่ได้ใน environment (`ModuleNotFoundError`) |
| Suite excluding `test_remote_tools.py` และ network-dependent `test_mcp_threat_intel.py` | จบรัน 100% ไม่มี failure เพิ่ม | ไม่พบ unexpected regression ใน suite ที่ environment รองรับ |
| Network-dependent MCP tests | Environment failure | URLhaus ถูก block ด้วย socket permission (`WinError 10013`) ไม่ใช่ test assertion regression |

ไม่แก้ test เพิ่มนอก allowlist และไม่แก้ dependency/environment ใน session นี้

### D5. Source research and documentation artifacts

- รายงาน feed research อยู่ที่ `scripts/adhoc/source_research.md` ครอบคลุม domain/hash
  non-API/no-auth sources, URL/format/cadence/license และ effort estimate
- เอกสาร rationale ถูกย้ายไป `scripts/eval/group_b_exclusion_rationale.md`
- `scripts/eval/eval_benchmark.py` และ `scripts/eval/fit_source_weights.py` ถูกย้ายออก
  จาก ignored `scripts/adhoc/`; path ภายในไฟล์ถูกอัปเดตให้ชี้ `scripts/eval/`
- `scripts/benchmark/build_benchmark_dataset.py` ไม่ย้ายและไม่แก้ เพราะ reference
  เดิมเป็น self-reference ของไฟล์เดียวกัน ไม่ใช่ `eval_benchmark.py`
- `scripts/adhoc/score_eval_results.py` ยังอยู่ที่เดิมตาม scope
- `.gitignore:97` เดิมไม่ถูกลบ; เพิ่ม `!scripts/eval/` และ `!scripts/eval/**` ที่
  `:99-100` เพื่อให้ evaluation tooling/documentation track ได้

### D6. Current handoff state

Git working tree มีการเปลี่ยนแปลงที่ตั้งใจไว้ใน source/scoring, tests, documentation
และไฟล์ใหม่ใน `scripts/eval/`; ยังไม่มี commit รอผู้ใช้ confirm ก่อน commit

### D7. Static-list fast-lane integration (historical pre-MISP): Smet NRD, HaGeZi NRD, and MalwareBazaar recent SHA256

**Session date:** 14 Sep 2026

**Context and scope.** These three sources were selected from
`scripts/adhoc/source_research.md` as effort-S, public static feeds. The
implementation follows the existing SSL Blacklist pattern in
`src/integrations/threat_feeds.py` (`_FeedCache` plus lazy TTL refresh), not the
uncached per-call URL pattern used by FeodoTracker and Tor exit nodes. The
scoring tier lists were intentionally left unchanged; all three sources use
the existing unknown-source fallback weight of `0.8`.

| Source | IOC type | Feed | Research context | Implemented semantics |
|---|---|---|---|---|
| Smet NRD | domain | `https://smet.cz/nrd/data/today.txt` | Public TXT feed, current-day/newly observed domains, updated throughout the day; CC BY 4.0 attribution; effort S | Lowercase exact domain membership in a cached set |
| HaGeZi NRD | domain | `https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt` | Public plain domain list, daily, GPL-3.0; NRD presence is not by itself a malicious verdict; effort S | Lowercase exact domain membership in a cached set |
| MalwareBazaar recent SHA256 | sha256 | `https://bazaar.abuse.ch/export/txt/sha256/recent/` | Public TXT export with comments/header and recent-only window; abuse.ch Terms/Fair Use require separate legal review; effort S | Exact lowercase membership for valid 64-character hexadecimal SHA256 values |

#### D7.1 Reference pattern and cache lifecycle

- `_FeedCache` remains the shared holder at `threat_feeds.py:64-75`:
  TTL, `last_update`, and an in-memory `Set[str]`.
- The common TTL is read from `config['timeouts']['feed_cache_ttl']` at
  `threat_feeds.py:112-114`, with the existing default of 3,600 seconds (one
  hour). No new hardcoded TTL was introduced.
- New cache instances are created per `ThreatFeeds` instance at
  `threat_feeds.py:125-128`: `_smet_nrd`, `_hagezi_nrd`, and
  `_mb_recent_sha256`.
- Each `_refresh_*_cache()` is lazy: the first check fetches the feed because
  the set is empty; later checks reuse it until `_FeedCache.is_stale()` says
  the shared TTL has expired. There is no startup job, cron integration, local
  feed snapshot, or persistent feed database.
- Refresh uses the existing `_session()` and `_fetch_text()` helpers. A
  successful refresh replaces the corresponding set and calls `mark_fresh()`.
- This feed cache is separate from `IOCCache`: the latter stores per-IOC result
  rows in `~/.blue-team-assistant/cache/ioc_cache.db` and is not the bulk feed
  snapshot.

#### D7.2 Source implementation

Implemented in `src/integrations/threat_feeds.py`:

- Feed constants: `:105-107`.
- Smet refresh/check: `:345-380`.
- HaGeZi refresh/check: `:386-421`.
- MalwareBazaar recent refresh/check: `:427-474`.
- Domain parsing strips whitespace/BOM, lowercases values, and skips blank,
  `#`, and `!` comment lines. Matching is exact set membership; there is no
  substring or regex matching.
- Hash parsing accepts only 64-character hexadecimal lines, lowercases them,
  and uses exact set membership. Header/comment lines are excluded by
  validation.
- Results use the existing `FeedResult` shape. A positive Smet/HaGeZi match
  returns score 85; a positive MalwareBazaar recent match returns score 95;
  clean results return `found: false` and score 0; exceptions return the
  standard error status.

The existing per-hash `check_malwarebazaar()` API lookup was not repurposed. It
still handles the single-hash `get_info` query; `check_mb_recent()` is a
separate bulk recent-export source.

#### D7.3 Comprehensive investigator wiring

Implemented in `src/integrations/threat_intel.py`:

- `source_defaults` includes `smet_nrd`, `hagezi_nrd`, and
  `mb_recent_sha256` at `:930-932`. This gives them `not_applicable: true`
  for unrelated IOC types.
- Domain tasks are appended under `if ioc_type == 'domain'` at `:991-999`.
- Hash tasks are appended under
  `if ioc_type in ['md5', 'sha1', 'sha256', 'hash']` at `:1012-1014`.
- `attempted_source_names` accounting includes a new source only when its
  task branch is selected, while defaults keep coverage explicit for other
  IOC types.

#### D7.4 Group A and untiered scoring decision

No new source was added to `GROUP_B_EXCLUDE`. The current code has no separate
Group A allowlist: any source not in `GROUP_B_EXCLUDE` is Group A by default
(`threat_intel.py:24-28`, `:1074-1076`; also
`intelligent_scoring.py:261-265`).

The three source names were intentionally not added to
`high_confidence_sources`, `medium_confidence_sources`, or
`low_confidence_sources`. Until a future verdict/scoring redesign assigns
explicit tiers, `IntelligentScoring` uses its unknown-source fallback weight
`0.8`. This decision is encoded as an explicit `UNTIERED_SOURCES` exemption
in `tests/test_threat_intel_source_accounting.py:59-63` rather than modifying
the scoring module.

NRD feeds indicate newly registered or recently observed domains, and recent
MalwareBazaar membership indicates recent sample presence. None of these
signals should be interpreted as an automatic standalone malicious verdict or
hard-block policy.

#### D7.5 Test fixture and accounting updates

Only the explicitly allowed test files were adjusted for the new task surface:

- `tests/test_threat_intel_cache_fallback.py:34-41` adds clean AsyncMocks for
  Smet and HaGeZi so cache/timeout tests for other sources do not fail during
  task construction.
- `tests/test_threat_intel_source_accounting.py:109-115` adds clean
  `check_mb_recent` to the SSL/wiring fixture.
- The hash accounting fixture at `:154-158` also supplies `check_mb_recent`,
  because the new source is genuinely scheduled for the hash lane.
- Hash accounting now reflects seven attempted sources, three clean Group A
  attempts, and 11 Group A not-applicable placeholders; Group B remains four
  attempted sources with nine not-applicable entries.
- The tier/task one-to-one test subtracts exactly
  `{'smet_nrd', 'hagezi_nrd', 'mb_recent_sha256'}` with a comment documenting
  the temporary fallback-weight decision.

#### D7.6 Verification evidence

| Check | Result | Evidence / interpretation |
|---|---:|---|
| `py_compile` | Pass | Compiled both integration files and both modified test files with `.venv\\Scripts\\python.exe`. |
| Targeted threat-intel tests | **9 passed** | Cache fallback, source accounting, fixture wiring, and untiered exemption all pass. |
| Full `.venv` pytest | **1350 passed, 0 failed** | `.venv\\Scripts\\python.exe -m pytest -q`; 8 subtests passed and 11 warnings remained. Runtime 66.94 seconds. |
| Live domain investigation | Pass | `example.com` through `investigate_ioc_comprehensive()` returned `smet_nrd` and `hagezi_nrd` in `sources` as clean, with no error/timeout. |
| Live hash investigation | Pass | Synthetic all-zero SHA256 through the same investigator returned `mb_recent_sha256` in `sources` as clean, with no error/timeout. |
| Diff/scope audit | Pass | Changes were limited to the two integration files and the two explicitly allowed test files before this documentation update; `git diff --check` passed; no commit was created. |

The first system-Python test attempt could not collect because `paramiko` was
missing, and an earlier sandboxed live attempt had HTTPS egress denied. The
final validation used the repository `.venv` and an approved network-enabled
run for the live feed checks.

#### D7.7 Remaining follow-up

- Decide explicit confidence tiers after the verdict/scoring redesign; remove
  the test exemption at that time.
- Add positive-match fixtures or controlled test feed responses if deterministic
  malicious examples are required; this session verified live wiring and clean
  non-error behavior, not a positive match for each feed.
- Revisit feed metadata/HTTP validators, attribution/legal handling, and any
  requirement for durable snapshots before production deployment.

### D8. MISP CIRCL public-feed integration (current session)

**Session date:** 15 Sep 2026

**Decision locked by user.** MISP is integrated as one additional source named
`MISP` in user-facing results. The implementation uses only the CIRCL public
OSINT feed (`manifest.json` plus `<event-uuid>.json`) and a full-feed
in-memory cache. MISP REST API, API credentials, per-IOC MISP network lookups,
and a user-selectable feed/API mode are explicitly out of scope.

The internal source/telemetry identifier is `misp_circl_feed_osint`; it is
intentionally separate from the existing `circl` passive-DNS integration and
the existing `circl_misp_feed_check()` function in
`src/mcp_servers/free_osint_tools.py`. Neither forbidden integration was
modified.

#### D8.1 Implementation and data model

- New module: `src/integrations/misp_feed.py`.
- Feed endpoints are defined at `misp_feed.py:23-24`:
  `https://www.circl.lu/doc/misp/feed-osint/manifest.json` and the event
  JSON URL template.
- `MISPFeed` owns an in-memory set index for `ip`, `domain`, `url`, and
  `hash`, plus per-event parsed values and timestamps. There is no persistent
  disk snapshot or database cache.
- `_parse_event()` reads both `Event.Attribute` and every
  `Event.Object[].Attribute` (`misp_feed.py:110-135`). Attribute mapping is:
  `ip-src/ip-dst -> ip`, `domain/hostname -> domain`, `url/uri -> url`,
  and MD5/SHA-family types (including `sha3-*`) -> `hash`.
- `check_misp(ioc, ioc_type)` performs local set membership only and returns
  `status`, `found`, `score`, `feed_status`,
  `latest_event_timestamp`, `cache_fetched_at`,
  `last_successful_refresh`, and refresh-failure metadata
  (`misp_feed.py:326-365`).
- A missing match is not reported as an unqualified clean result when the feed
  is `stale` or `unavailable`; it uses the warning status and preserves
  freshness metadata.

#### D8.2 Refresh lifecycle and FIX 1-3

- The first IOC check lazily schedules a background full-feed refresh. The
  check itself does not await network activity, so the first result may be
  `unavailable` or `stale` while refresh is running.
- Refresh is incremental after the initial load. `_cursor_timestamp` is the
  global timestamp cursor (`misp_feed.py:53-57`, `:252-263`); the
  per-event timestamp map remains the retry-safe fallback for events that
  failed during a partial cycle.
- **FIX 1 — partial failures:** the cycle calculates `failures / total` at
  `misp_feed.py:293-307`. A maximum 10% failure ratio is treated as an
  acceptable refresh; if any event succeeded, `cache_fetched_at` and
  `latest_event_timestamp` are updated first (`:216-222`). Ratios above
  10% retain the successful event updates but keep failure/backoff state
  active. A manifest/session failure counts as a full refresh failure.
- **FIX 2 — one session:** `_refresh_events()` opens one
  `aiohttp.ClientSession` around manifest and all event requests
  (`misp_feed.py:229-234`, `:264-274`). The same session is passed to
  `_refresh_manifest()` and `_fetch_event()`.
- **FIX 3 — scheduling gate:** `_schedule_refresh()` checks both
  `_next_refresh_at` and `_circuit_open_until` before checking/creating a
  task (`misp_feed.py:312-324`).
- Refresh circuit settings are intentionally conservative: three consecutive
  failed cycles open the circuit; cooldown starts at 900 seconds and uses
  exponential backoff capped at one hour (`misp_feed.py:27-31`, `:194-205`).
  Existing cache data remains available as stale-but-usable data.

#### D8.3 Threat-intelligence wiring and classification

- `ThreatIntelligence` constructs `MISPFeed` at
  `src/integrations/threat_intel.py:77-78`.
- `source_defaults` includes the all-four-type capability message at
  `threat_intel.py:936`, so unrelated IOC types are marked not applicable.
- The same source is appended once in each supported task branch:
  IPv4 `:969`, domain `:997`, URL `:1009`, and hash `:1020`.
- `GROUP_B_EXCLUDE` was not changed. Under the current legacy accounting,
  sources absent from that set are Group A by default; this is separate from
  explicit confidence-tier assignment.
- MISP is intentionally provisional/untiered. It was added to the
  `UNTIERED_SOURCES` test exemption with the existing fallback-weight comment
  (`tests/test_threat_intel_source_accounting.py:59-68`).
  `src/scoring/intelligent_scoring.py` was not modified.

#### D8.4 Test changes and verified results

- `tests/test_threat_intel_cache_fallback.py:42-52` adds a clean async
  `check_misp` mock so unrelated cache/timeout tests do not perform MISP work.
- `tests/test_threat_intel_source_accounting.py:121-132` and `:174-185`
  provide clean MISP mocks for the wire and hash fixtures.
- Hash accounting was updated from 7 to 8 attempted sources. The actual hash
  task list contains eight sources because MISP is now scheduled at
  `threat_intel.py:1019-1027`. The fixture therefore correctly expects four
  clean Group-A attempts and four Group-A attempted sources at
  `tests/test_threat_intel_source_accounting.py:204-220`; this is test
  accounting, not a new score or tier decision.
- `.venv\\Scripts\\python.exe -m py_compile` passed for all four changed or
  created implementation/test files.
- MISP parser smoke test passed with synthetic attributes covering all four
  normalized IOC types from both event attribute locations.
- Targeted cache/accounting tests: **9 passed**.
- Full suite with workspace temp isolation: **1348 passed, 2 failed**. The two
  failures were pre-existing live URLhaus tests blocked by socket policy
  (`WinError 10013`), not MISP failures. Re-running with only those two tests
  deselected produced **1348 passed, 2 deselected**.
- No live CIRCL full-feed download was performed in this implementation
  session, so event-count coverage, feed freshness in production, and positive
  MISP matches remain unverified. The integration is therefore wired and
  parser-verified, but live-feed evidence is still T2 rather than T1.

#### D8.5 Commit and remaining follow-up

- Implementation commit: `24b8adf` (`Integrate CIRCL MISP feed cache`). It
  contains exactly the four approved files:
  `misp_feed.py`, `threat_intel.py`,
  `test_threat_intel_cache_fallback.py`, and
  `test_threat_intel_source_accounting.py`.
- This ledger update is a separate documentation change and is intentionally
  not included in that implementation commit.
- Follow-up before treating MISP as a permanent tier: run a controlled/live
  CIRCL refresh, measure event success ratio and freshness over time, inspect
  positive-match behavior, and then decide explicit confidence-tier placement
  without conflating it with Group A/B execution accounting.

## D9. Evidence-based source tiering and resilient execution redesign
   (historical pre-AHP plan, superseded for production scoring)

### หัวข้อใหญ่

งานชุดนี้คือการเปลี่ยนจากการจัด tier ของ source จากโครงสร้างโค้ดหรือการคาดเดา ไปเป็นการจัดลำดับความสำคัญจากหลักฐานการทำงานจริงของแต่ละ source โดยแยกประเด็นที่มักถูกปนกันออกเป็นคนละแกน:

- **Execution tier**: ควรเรียก source ใดก่อนเพื่อประหยัดเวลา ลดการพึ่งพา network และลดโอกาสชน API quota
- **Evidence reliability**: source ทำงานสำเร็จ สม่ำเสมอ สด และมี latency อยู่ในระดับใด
- **Content credibility**: เนื้อหาที่ source รายงานมีความน่าเชื่อถือเชิงภัยคุกคามเพียงใด
- **Group A/B**: ขอบเขตที่ระบบ scoring ปัจจุบันอนุญาตให้นำ source ไปใช้

การแยกสี่เรื่องนี้มีเป้าหมายไม่ให้ source ที่เรียกง่ายหรือเร็วถูกตีความว่าเนื้อหาถูกต้องกว่าโดยอัตโนมัติ และไม่ให้ source ที่ใช้ API ถูกตัดสินว่าไม่น่าเชื่อถือเพียงเพราะมี quota สำหรับ execution tier นี้ SOCPOW ให้ความสำคัญกับ non-API, local/cache lookup และ coverage ที่กว้าง เพราะตรงกับเป้าหมายการประหยัดเวลาและลด dependency ภายนอก

### สถานะรวม (historical snapshot)

**สถานะเดิม:** กำลังเก็บหลักฐาน — ยังไม่พร้อมล็อก tier หรือแก้ scoring logic

แผน D9 นี้ถูกเขียนก่อนการตัดสินใจ AHP และยังคงไว้เพื่อ audit trail เท่านั้น
ขั้นตอน D9.4–D9.10 ที่ระบุให้ทำ tier report แล้วจึงแก้ scoring ไม่ใช่ blocker
ของ production policy ปัจจุบันอีกต่อไป เพราะ current session ได้ล็อก AHP
matrices, CR, admission boundary และ multipliers ไว้ใน section ด้านบนแล้ว
งานที่ยังเปิดใน D9 ให้ตีความเป็น future validation/resilience work ไม่ใช่
คำสั่งให้ย้อนกลับไปใช้ legacy `1.5/1.0/0.5/0.8` mapping

MISP มีสถานะ wired/parser-verified แล้ว แต่ยังไม่มี empirical production evidence จากการ refresh full feed จริงเพียงพอสำหรับตัดสิน tier ถาวร แผนด้านล่างจึงกำหนดลำดับตั้งแต่การตรวจ feed, เก็บ telemetry, ตรวจความพร้อมของ dataset, คำนวณ metrics, ทำ tier report, ไปจนถึงการแก้ scoring หลังได้รับ approval เท่านั้น

### เกณฑ์สถานะ

- `[x]` ทำตามขอบเขตของขั้นตอนนั้นแล้ว
- `[ ]` ยังไม่เสร็จ หรือทำได้เพียงบางส่วนและยังใช้เป็นหลักฐานตัดสิน tier ไม่ได้

## D9.1 ขั้นที่ 1 — ตรวจ MISP live feed แบบ read-only

**วัตถุประสงค์:** ยืนยันพฤติกรรมของ CIRCL public MISP feed จากการทำงานจริง ไม่สรุปจาก parser หรือจำนวน type ที่รองรับในโค้ดเพียงอย่างเดียว

**วิธีทำ:** fetch `manifest.json` แบบ read-only และบันทึกจำนวน event; fetch event ตาม manifest แล้วนับ success/failure; parse ทั้ง `Event.Attribute` และ `Event.Object[].Attribute`; normalize เป็น `ip`, `domain`, `url`, `hash`; บันทึก `latest_event_timestamp`, เวลา refresh และระยะเวลารวม; จากนั้นทดสอบ partial failure และ stale-cache เพื่อยืนยันว่า event ที่สำเร็จยังใช้ได้ และ `found=false` จาก feed ที่ stale/unavailable ไม่ถูกตีความว่า clean

**ทำเพื่ออะไร:** แยกให้เห็นว่า feed มีข้อมูลอะไร, refresh เชื่อถือได้เพียงใด และผลไม่พบ IOC มีความหมายเป็น clean หรือเป็นเพียง feed stale/unavailable

**ผลลัพธ์ที่ต้องได้:** หลักฐาน live ที่ระบุ event count, success/failure count, IOC coverage, freshness, refresh latency และพฤติกรรม partial-failure/stale-cache ได้ครบ

**สถานะ:** `[ ]` ยังไม่เสร็จ

**หลักฐานปัจจุบัน:** MISP ถูก wire และตรวจ parser แล้ว แต่ ledger เดิมระบุว่ายังไม่มีการรัน full-feed live ที่ใช้เป็น empirical production evidence จึงยังไม่มีตัวเลข CIRCL จริงสำหรับ event count, refresh duration และ failure ratio ที่จะใช้ล็อก tier

**ข้อสรุปชั่วคราว:** MISP คงสถานะ `provisional/untiered` ไม่ใช่ Tier A จากการมีโค้ดหรือ coverage ที่ออกแบบไว้

## D9.2 ขั้นที่ 2 — สร้าง telemetry collector

**วัตถุประสงค์:** สร้างวิธีวัด behavior ของ source ให้เป็นรูปแบบเดียวกันต่อ `source × IOC type` และเก็บ raw result เพื่อวิเคราะห์ซ้ำได้

**วิธีทำ:** collector เก็บ `source`, `ioc_type`, `timestamp`, `success/fail`, `latency_ms`, `error_type`, `cache_hit`, `feed_status` และ `found` โดยแยก latency เป็น `cold_refresh_latency`, `warm_cached_lookup_latency` และ `api_request_latency` เพราะ static feed ที่ query จาก memory ไม่ควรถูกเปรียบเทียบกับ API call ที่มี network และ quota แบบเดียวกัน

**คำสั่งที่ใช้:**

```powershell
.venv\Scripts\python.exe scripts\adhoc\collect_source_telemetry.py `
    --source smet_nrd `
    --ioc example.com `
    --ioc-type domain `
    --repeat 3 `
    --output evidence\source_telemetry.jsonl
```

**ตัวอย่างผลลัพธ์:**

```json
{
  "source": "smet_nrd",
  "ioc_type": "domain",
  "success": true,
  "fail": false,
  "latency_ms": 611.6,
  "latency_class": "cold_refresh",
  "cache_hit": false,
  "found": false
}
```

Warm lookup รอบถัดไปใช้เวลาประมาณ `0.0 ms` และมี `cache_hit=true`

**ทำเพื่ออะไร:** สร้างหลักฐานเชิงตัวเลขสำหรับ access mode, latency, cache behavior และ error behavior โดยไม่เหมารวม static/cache source กับ API source

**ผลลัพธ์:** มี collector ที่รันได้ มีการตรวจ `py_compile` และ source inventory แล้ว และยังไม่ได้ใช้ `--all-sources` เพื่อป้องกันการเรียก API quota โดยไม่ตั้งใจ

**สถานะ:** `[x]` สร้าง collector และทดสอบตัวอย่างแล้ว; `[ ]` การเก็บระยะยาวและการเก็บครบทุก source ยังไม่เสร็จ

**หลักฐาน:** `scripts/adhoc/collect_source_telemetry.py` และ output ที่บันทึกไว้ใน `evidence/` ตามคำสั่งข้างต้น

## D9.3 ขั้นที่ 3 — กำหนด sample และ protocol ให้ตายตัวก่อนรันจริง

**วัตถุประสงค์:** ป้องกันการจัด tier จาก sample เล็กหรือชุดข้อมูลที่เอนเอียง และทำให้ผลจากคนละช่วงเวลาทำซ้ำและเปรียบเทียบกันได้

**วิธีทำ:** เก็บอย่างน้อย 30 samples ต่อ `source × IOC type`; แยก `known-malicious` และ `known-clean` พร้อม provenance/วันที่ยืนยัน; ไม่เรียก source กับ IOC type ที่ไม่รองรับ; เก็บผลดิบทุก call; รันซ้ำหลายช่วงเวลาเพราะ latency, rate-limit, freshness และ availability เปลี่ยนตามเวลา; แยก cold refresh, warm lookup และ API request ตาม schema ข้อ 2

**ทำเพื่ออะไร:** ทำให้ `n`, success rate, error rate, p95 และ cache stability สะท้อนพฤติกรรมจริง ไม่ใช่ผลจากการทดลองครั้งเดียวหรือ IOC ชนิดเดียว

**ผลลัพธ์ที่ต้องได้:** sampling manifest ที่ระบุ source/type, รายการ IOC, label malicious/clean, ช่วงเวลารัน และ raw telemetry ที่ครบ minimum sample

**สถานะ:** `[x]` หลักเกณฑ์และ protocol ถูกกำหนดแล้ว; `[ ]` ยังเก็บ sample ครบตาม minimum และหลาย time window ไม่เสร็จ

**หลักฐาน:** `evidence/source_telemetry_2026-09-15/source_telemetry_report.md:34-37` กำหนด minimum known-malicious/known-clean และ readiness validation; รายงานเดียวกันระบุ dataset ปัจจุบันยังไม่พร้อมในบาง IOC type ที่ `:56-58`

### D9.3a Window 1 results (2026-09-15)

- Raw telemetry: `evidence/reliability_sampling/windows/window1_2026-09-15.jsonl`
- Result: `3,365` rows in one clean window; validation found no duplicate block and monotonically increasing timestamps.
- Sources covered (13): `feodotracker`, `c2_trackers`, `spamhaus`, `usom`, `tor_exit_nodes`, `circl`, `sslblacklist`, `smet_nrd`, `hagezi_nrd`, `mb_recent_sha256`, `threatfox`, `urlhaus`, `malwarebazaar`.
- `talos` excluded from scoring/reliability sampling — confirmed non-functional (120/120 fail across 2 runs in window1, DNS SenderBase timeout ~5s matching configured timeout, root cause: service deprecated per source code comment). Effective source count: 13 (was 14). Excluded from window1 metrics retroactively via filter at compute time; raw window1 jsonl file unmodified for evidence integrity.
- Excluded: `misp_circl_feed_osint` (separate MISP live-feed validation step) and the 13 Group B API-key sources: `virustotal`, `abuseipdb`, `shodan`, `alienvault`, `greynoise`, `censys`, `pulsedive`, `criminalip`, `ipqualityscore`, `phishtank`, `ip2proxy`, `triage`, `threatzone`.
- Key findings:
  - `talos`: `60/60` failures in this window and `120/120` failures including the prior invalid run. DNS SenderBase lookup timed out at approximately `5,000 ms`, matching the resolver timeout in `threat_intel_extended.py:105-106`. Evidence indicates the service is deprecated, not a SOCPOW code-path bug. See `evidence/reliability_sampling/invalid_runs/README.md`.
  - `tor_exit_nodes`: `0` failures in this clean window. The prior `429` responses came from duplicated concurrent load, so the prior `429` is not treated as normal source behavior.
  - `malwarebazaar`: `1/60` failure (`5xx`) in window1; no failures in
    windows 2 and 3.
- Window status: `[x]` all 3/3 minimum time windows complete (window1
  talos-filtered, window2 clean, window3 clean).
- No scoring or tier code was changed in this run, per the D9 gate.

### D9.3b Window 2 first run invalid (2026-09-15)

- Quarantined raw telemetry: `evidence/reliability_sampling/invalid_runs/window2_2026-09-15_ENV_BLOCK_INVALID.jsonl`
- The first window 2 run is invalid and must be rerun after host connectivity is restored. Local socket rejection (`[Access is denied]`) caused `540/1,205` executable rows to fail across `feodotracker`, `threatfox`, `circl`, `tor_exit_nodes`, `urlhaus`, and `malwarebazaar`; failures were approximately sub-millisecond to `132 ms`, with no timeout or HTTP error.
- The quarantined run is excluded from reliability metrics; the valid window 2
  collection is recorded in the next bullet.
- Window2 valid run confirmed 2026-09-15 09:45:45–09:58:08 UTC (743.3s). Root cause of earlier invalid attempts: stale Codex sandbox firewall rules (`codex_sandbox_offline_block_*`) blocking outbound HTTPS at local socket layer — removed manually, confirmed via direct curl test. One additional transient timeout to `check.torproject.org` occurred on 2nd rerun attempt (no output written, non-retry per protocol); 3rd attempt succeeded with zero failures across all 1,205 executable rows, 13 sources, no talos. Effective dataset: window1 (talos-excluded, 3,365 rows) + window2 (3,125 rows, 100% success).

### D9.3c Window 3 results (2026-09-15)

- Raw telemetry: `evidence/reliability_sampling/windows/window3_2026-09-15.jsonl`
- Run: `2026-09-15T12:14:16.851Z–12:24:12.109Z` UTC (`595.3s`).
- Result: `3,125` rows from the original 240-record sample and 13 explicit
  sources; `1,205` executable rows and `1,920` not-applicable rows.
- Success: `1,205/1,205` executable rows succeeded; no talos was called.
  Expected-label breakdown: `MALICIOUS 600/600` success and `CLEAN 605/605`
  success.
- Error type breakdown: `401=0`, `429=0`, `5xx=0`, `timeout=0`,
  `other=0`, `none=1,205`.
- Sequence validation: `source_block_count=13`, source order matched the
  locked 13-source order, timestamps were monotonic, and
  `duplicate_timestamp_block_count=0`.
- Reliability collection is now complete: `3/3` valid windows — window1
  talos-filtered, window2 clean, and window3 clean.

## D9.4 ขั้นที่ 4 — สร้าง coverage matrix จากข้อมูลจริง

**วัตถุประสงค์:** แยกคำว่า “รองรับ type” ออกจาก “มีข้อมูลไม่ว่าง” และ “มี match ใน sample” ซึ่งเป็นคนละข้อเท็จจริง

**วิธีทำ:** ทำตารางแยก source และ IOC type โดยตรวจสี่มิติ: รองรับตามโครงสร้าง feed/check function; มีข้อมูล non-empty ใน feed/index จริง; มี match ใน known-malicious หรือ sample จริง; และมี error/timeout/schema failure ใน type นั้นหรือไม่

ห้ามใช้ `match_rate > 0` เป็น coverage เพียงอย่างเดียว เพราะ sample อาจไม่มี malicious IOC ที่ source นั้นรู้จัก การไม่มี matchจึงไม่เท่ากับ source ไม่มีข้อมูลหรือไม่มีความครอบคลุม

**ทำเพื่ออะไร:** ป้องกันการให้คะแนน coverage สูง/ต่ำผิดจากการเลือก sample และทำให้เห็นช่องว่างระหว่าง capability ตามโค้ดกับข้อมูลที่ source มีจริง

**ผลลัพธ์ที่ต้องได้:** coverage matrix พร้อม denominator, sample count, non-empty evidence, match count และ error count ต่อ cell

**สถานะ:** `[ ]` ยังไม่เสร็จ เพราะยังไม่มี matrix ที่คำนวณจาก telemetry และ live feed ครบทุก source/type

## D9.5 ขั้นที่ 5 — คำนวณ reliability และ execution metrics

**วัตถุประสงค์:** เปลี่ยน raw telemetry ให้เป็น metrics ที่ reproducible ก่อนนำไปจัด tier

**วิธีทำ:** คำนวณแยก source/type และบันทึกสูตร/threshold คู่กับผลลัพธ์ ได้แก่ Access Mode Score, Coverage Score จาก feed/data จริง, Wilson lower bound ของ success rate ที่ confidence 95%, p95 latency แยกตาม latency class, rolling error rate, cache stability และ refresh freshness จาก `latest_event_timestamp`, `cache_fetched_at` และ feed status

ต้องล็อก threshold ก่อนเห็นผล aggregate เพื่อไม่ให้เปลี่ยนเกณฑ์ย้อนหลังให้เข้ากับ source ที่ต้องการ

**ทำเพื่ออะไร:** ทำให้การตัดสินใจตรวจสอบซ้ำได้ และแยก execution priority ออกจาก content credibility และ verdict weight

**ผลลัพธ์ที่ต้องได้:** metrics artifact ที่มีสูตร, threshold, sample size, confidence method และผลต่อ source/type ครบถ้วน

**สถานะ:** `[ ]` ยังไม่เสร็จ; ตอนนี้มีแนวทางและสูตรระดับ design แต่ยังไม่มีผลคำนวณจาก telemetry ที่ครบและ threshold artifact ที่ผ่าน approval

## D9.6 ขั้นที่ 6 — จัด tier เป็นรายงานก่อนแก้ scoring

**วัตถุประสงค์:** ให้คนตรวจหลักฐานและอนุมัติการจัด tier ก่อนเปลี่ยน behavior ของ production scoring

**วิธีทำ:** สร้างตาราง `source | access mode | coverage | n | Wilson lower bound | p95 latency | error rate | cache stability | provisional/tier` พร้อม raw evidence links, assumptions และ unresolved gaps แล้วแสดงแยกกันระหว่าง Execution tier, Evidence reliability, Content credibility และ Group A/B

MISP ต้องคง `provisional/untiered` จนกว่าจะมีหลักฐาน live และ sample เพียงพอ ไม่ใช่ยกระดับเพราะเป็น MISP หรือเพราะ index รองรับสี่ IOC type ตาม design

**ทำเพื่ออะไร:** ทำให้การจัด tier เป็น decision record ที่ตรวจสอบได้ และลดความเสี่ยงที่การเปลี่ยน tier จะไปเปลี่ยน verdict โดยไม่มีหลักฐานรองรับ

**ผลลัพธ์ที่ต้องได้:** tier recommendation report พร้อม evidence, assumptions, gaps และ approval record

**สถานะ:** `[ ]` ยังไม่เสร็จ เพราะยังไม่มีตาราง metrics/tier จากข้อมูลจริงและยังไม่มี approval ให้แก้ scoring

## D9.7 ขั้นที่ 7 — ออกแบบ Circuit Breaker ให้ครบ source ที่จำเป็น

**วัตถุประสงค์:** ป้องกัน source ที่กำลังล้มเหลวหรือช้าผิดปกติทำให้ investigation ทั้งชุดช้า/พัง และควบคุม retry ไม่ให้เพิ่มปัญหา rate limit

**สถานะปัจจุบัน:** MISP มี circuit breaker เฉพาะ refresh และ fallback ไปใช้ stale cache ได้ แต่ยังไม่ใช่ policy กลางที่ใช้กับทุก source

**วิธีทำที่ต้องตัดสินใจก่อน implement:** เลือกว่าจะทำ breaker ในแต่ละ integration หรือ wrapper กลางใน investigator; กำหนด `closed`, `open`, `half-open`; ล็อก failure window, threshold, cooldown/backoff และ probe count; แยก refresh failure, quota/401, timeout, schema error และ stale-cache semantics; และกำหนดการบันทึก failure โดยไม่ทำให้ `sources_checked` หรือ verdict บิดเบือน

**ทำเพื่ออะไร:** ทำให้ resilience behavior สม่ำเสมอและควบคุม unstable dependency โดยไม่ปะปนกับ reliability/content score

**ผลลัพธ์ที่ต้องได้:** design ที่ได้รับ approval และ state machine/policy ที่ทดสอบได้สำหรับ source ใน scope

**สถานะ:** `[ ]` ยังไม่เสร็จ; มีเพียง MISP-specific implementation ยังไม่มีการตัดสินใจหรือ implementation แบบกลางสำหรับทุก source

## D9.8 ขั้นที่ 8 — แก้ scoring/tier logic หลัง approval

**วัตถุประสงค์:** นำ tier recommendation ที่มีหลักฐานไปใช้จริงโดยไม่แก้ scoring ก่อนข้อมูลพร้อม

**วิธีทำหลังได้รับ approval เท่านั้น:** เพิ่ม explicit source-to-tier mapping; ลบหรือปรับ `UNTIERED_SOURCES`; ตัดสินใจว่าจะคง fallback weight `0.8` หรือเปลี่ยนจากผล evidence; เพิ่ม tests สำหรับ threshold, Wilson bound, provisional gate และ circuit state; ตรวจว่า execution tier, Group A/B และ confidence/content weight ยังเป็นคนละแนวคิด

**ทำเพื่ออะไร:** ลดความเสี่ยงของการ lock-in design จากข้อมูลไม่พอ และทำให้ทุกการเปลี่ยน scoring มีเหตุผลกับหลักฐานที่ตรวจย้อนหลังได้

**ผลลัพธ์ที่ต้องได้:** code change ที่ผ่าน approval, tests และ ledger decision record ที่ชี้ว่า source ใดเปลี่ยน tier ด้วยเหตุผลใด

**สถานะ:** `[ ]` ยังไม่เริ่ม เพราะยังรอ live evidence, metrics report และ approval

## D9.9 ขั้นที่ 9 — Regression และ operational behavior

**วัตถุประสงค์:** ตรวจว่าการจัด tier/resilience ใหม่ไม่ทำให้ investigation เดิมเสียหาย และ behavior ตอนใช้งานจริงสอดคล้องกับ design

**วิธีทำ:** ตรวจ cache หลัง restart; ทำให้ feed stale แล้วตรวจ `feed_status` และความหมายของ `found=false`; ทำให้ source ล้มเหลว/timeout แล้วตรวจว่า investigation อื่นยังทำงานต่อ; ตรวจ `sources_checked`, coverage และ attempted/clean accounting; ตรวจว่า Group A/B ไม่ปนกับ confidence tier; และรัน unit/integration/regression tests เทียบ baseline

**ทำเพื่ออะไร:** ยืนยัน correctness, failure isolation และความหมายของข้อมูลที่ผู้ใช้เห็น ไม่ใช่ตรวจเฉพาะสูตรคำนวณ

**ผลลัพธ์ที่ต้องได้:** regression report, operational test evidence และ known limitations ที่ยังต้องติดตาม

**สถานะ:** `[ ]` ยังไม่เสร็จ; จะทำหลัง design และ tier report ได้รับ approval

## D9.10 ลำดับงานที่ควรทำต่อ (historical pre-AHP sequence)

1. `[ ]` Live-validate MISP full feed แบบ read-only และเก็บหลักฐาน raw/summary
2. `[x]` ใช้ telemetry collector ที่สร้างแล้วเพื่อกำหนด schema และทดลองเก็บ behavior
3. `[ ]` เก็บ sample ให้ครบตาม minimum ต่อ source/type และหลายช่วงเวลา
4. `[ ]` คำนวณ coverage matrix และ reliability/execution metrics จาก raw evidence
5. `[ ]` ออกรายงาน tier ให้ตรวจและอนุมัติก่อนแก้ scoring; หลังจากนั้นจึงออกแบบ circuit breaker กลางและทำ regression

**ข้อสรุป:** ทิศทาง MCDA + Wilson lower bound + Circuit Breaker เป็นกรอบการทำงานที่เหมาะกับโจทย์นี้ในระดับ design แต่ tier ที่น่าเชื่อถือยังต้องรอหลักฐานจากการรันจริง ไม่ควรสรุปจากชื่อ source, การมี/ไม่มี API key หรือ parser coverage เพียงอย่างเดียว

## D10. Role-based login and RBAC (advisor requirement)

### หัวข้อใหญ่

นี่คือ requirement จากอาจารย์: ระบบต้องมี login แบ่ง 3 role ตาม Target User ได้แก่ `SOC Analyst Tier 1-2`, `Incident Responder` และ `Threat Hunter` โดยแต่ละ role เห็นข้อมูลและ flow ต่างกัน และต้องสามารถผูก Gmail ของ user แต่ละคนเข้ากับระบบแจ้งเตือนได้

**Amendment (ยังไม่มี verbatim quote; session date ยังไม่ได้บันทึก):** อาจารย์สั่งเพิ่ม role ที่ 4 คือ `Team Lead` เข้าไปในระบบ ต้องขอคำสั่งฉบับเต็มแบบคำต่อคำจากอาจารย์มาบันทึกแทนที่ข้อความ amendment นี้ภายหลัง

### สถานะรวม

Phase 1, Phase 1.5, Phase 2 และ Phase 2.5 เสร็จแล้ว; Team Lead Phase 1–3
เสร็จแล้วตาม D10.8; generic per-flow filtering, Gmail OAuth และ notification
routing ราย user ยังไม่เริ่ม

### เกณฑ์สถานะ

- `[x]` ทำตามขอบเขตของขั้นตอนนั้นแล้ว
- `[ ]` ยังไม่เสร็จ หรือรอ phase ก่อนหน้า/approval ที่เกี่ยวข้อง

## D10.1 Phase 1 — Auth core (login/logout, JWT session)

**วัตถุประสงค์:** เพิ่ม authentication core สำหรับ login/logout, password hashing, JWT session issuance/verification และ session revocation

**วิธีทำ:** ใช้ bcrypt password hashing, HMAC-SHA256 JWT และ `get_current_user()` FastAPI dependency พร้อม `auth_sessions` สำหรับ revoke session

**ทำเพื่ออะไร:** ให้ระบบมีตัวตนของ user และ session ที่ตรวจสอบได้ก่อนเพิ่ม authorization

**ผลลัพธ์ที่ต้องได้:** endpoint login/logout และ current-user dependency ที่ใช้งานได้

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐาน:** `git log --oneline -- src/web/auth.py src/web/routes/auth.py` ยืนยัน commit `5b07b86 Add Phase 1 auth core: login/logout with JWT sessions`

## D10.2 Phase 1.5 — Admin invite-only registration

**วัตถุประสงค์:** ให้ admin เพิ่มสมาชิกใหม่แบบ invite-only โดยผู้ใช้ไม่สามารถสมัครหรือเลือก role ด้วยตัวเอง

**วิธีทำ:** ใช้ `POST /api/admin/users/invite` สำหรับ admin และ `POST /api/auth/accept-invite` สำหรับรับ invite, token ใช้ครั้งเดียวและหมดอายุใน 48 ชั่วโมง

**ทำเพื่ออะไร:** ควบคุมการเพิ่ม user และ role จากฝั่ง admin โดยตรง

**ผลลัพธ์ที่ต้องได้:** user ใหม่ถูกสร้างเป็น inactive ก่อน แล้วจึง activate พร้อม username/password จาก invite

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐาน:** commit `76670cd Add Phase 1.5: admin invite-only registration`

**Endpoint ที่มี:** `POST /api/admin/users/invite`, `POST /api/auth/accept-invite`

**Design decision:** ไม่มี teams table แยก ใช้ทีมเดียวโดย implicit; admin เพิ่มสมาชิกโดยตรงผ่าน email; ผู้ใช้ไม่มี self-select role; มี 4 role ได้แก่ 3 target-user role และ `admin`

## D10.2.5 Phase 2.5 — Session ownership (known gap from Phase 2)

**วัตถุประสงค์:** ปิดช่องว่างด้าน session ownership ที่พบระหว่างทำ Phase 2 โดยเป็น sub-task ค้างของ Phase 2 ไม่ใช่ phase ใหม่ที่แยกอิสระ

**ช่องว่างที่พบ:** `AgentStore.get_session()` และ `AgentStore.list_sessions()` เดิมไม่มี `user_id` parameter และ `chat.py` ไม่ได้ส่ง user scope เข้าไป ทำให้ session read ยังไม่ owner-scoped; การตรวจสอบเพิ่มเติมพบว่า `analysis.py` ไม่มี RBAC และ `reports.py`/`dashboard.py` มี endpoint ที่ยังไม่ป้องกันด้วย auth ด้วย

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐานการดำเนินการ:**

- `22de643 Add Phase 2.5 session ownership storage layer` — migration เพิ่ม nullable `user_id` ใน `agent_sessions` และ `analysis_jobs`, backup/transaction/restore เมื่อ migration ตัวที่สองล้มเหลว, และส่ง owner scope ผ่าน AgentStore, AnalysisManager, AgentLoop และ PlaybookEngine
- `853cd7e Add Phase 2.5 RBAC routes and WebSocket ownership controls` — owner filter สำหรับ chat/agent/dashboard recent และ owner check สำหรับ `/ws/agent`; shared role-based access สำหรับ analysis/reports/dashboard aggregate และ `/ws/analysis`
- `6db8514 Add Phase 2.5 ownership and RBAC test coverage` — migration rollback, owner filtering, NULL-owner policy, route role matrix และ WebSocket coverage

**Access model ที่เสร็จแล้ว:**

- Private/owner-scoped: chat sessions, agent session REST endpoints, `/ws/agent/{session_id}` และ `GET /api/dashboard/recent`; `admin` เห็นทั้งหมด ส่วน role อื่นเห็นเฉพาะ `user_id` ของตนเอง
- Shared/role-based: `/api/analysis/*` เฉพาะ `SOC Analyst Tier 1-2`/`admin`; reports read ทุก authenticated role, rule update เฉพาะ `Threat Hunter`/`admin`, approve/mark-deployed เฉพาะ `Incident Responder`/`admin`; dashboard stats/sources และ `/ws/analysis/{analysis_id}` ทุก authenticated role

**Legacy records:** `agent_sessions` 4 rows และ `analysis_jobs` 104 rows เดิมไม่มีหลักฐานระบุ owner จึงคง `user_id = NULL`; endpoint ที่ owner-filter จะ exclude แถวเหล่านี้สำหรับ non-admin โดยธรรมชาติ และ admin เห็นได้ทั้งหมด ส่วน reports/shared workflow ไม่ใช้ owner filter

**Testing evidence:** migration failure scenario restore กลับแบบ byte-exact และ migration จริง exit code 0; `tests/test_rbac_middleware.py` ล่าสุด `132 passed`, ownership/RBAC/API suite `176 passed`, regression suite `12 passed`, `py_compile` 13 ไฟล์ผ่าน และ `git diff --check` ผ่าน

**Response contract:** owner resource ที่ไม่มีอยู่หรือไม่ใช่ของ current user คืน `404` เหมือนกันเพื่อป้องกัน ID enumeration; role mismatch คืน `403`; collection ว่างคืน `200` พร้อม `[]`

**สถานะเดิมที่แก้แล้ว:** เดิมจำกัด `GET /api/chat/sessions` และ `GET /api/chat/sessions/{id}` ให้ `admin` เท่านั้นเป็น mitigation ชั่วคราว; ปัจจุบันใช้ owner filter แล้ว

**ขอบเขตที่ดำเนินการแล้ว:** ทำ schema migration เพิ่ม nullable `user_id` พร้อม backup/transaction/restore, คง legacy records เป็น `NULL` ตามหลักฐานที่มี, แก้ AgentStore/AnalysisManager ให้รับและใช้ owner filter, ส่ง `current_user["id"]` ผ่าน AgentLoop/PlaybookEngine และ routes, เพิ่ม role/ownership enforcement ใน REST และ WebSocket, และเพิ่ม regression/rollback tests

## D10.3 Phase 2 — RBAC middleware

**วัตถุประสงค์:** บังคับสิทธิ์ตาม role กับ route และ flow ที่มีอยู่

**วิธีทำ:** ใช้ `require_role()` dependency ที่มีแล้วจาก Phase 1.5 ซึ่งถูกใช้กับ admin-only endpoint แล้ว และนำไป apply กับ route ของ Flow A/B/C ได้แก่ `agent.py`, `playbooks.py`, `chat.py` และ `websocket.py` ตาม 3 target-user role

**ทำเพื่ออะไร:** แยกสิทธิ์การเข้าถึงข้อมูลและ action ระหว่าง role อย่างเป็นระบบ

**ผลลัพธ์ที่ต้องได้:** route ที่เกี่ยวข้องมี role enforcement และ unauthorized access ได้ response ที่ถูกต้อง

**สถานะ:** `[x]` เสร็จแล้ว

**หลักฐาน:** commit `2220a60 Add Phase 2: RBAC middleware for Flow A/B/C routes and WebSockets`

**สรุป route → role (Phase 2 baseline และการขยายใน Phase 2.5):** `agent.py` ใช้ `Threat Hunter`/`admin`; `playbooks.py` ใช้ `Incident Responder`/`admin`; `chat.py` ใช้ `Incident Responder`/`admin` เมื่อมี `playbook_id` และ `Threat Hunter`/`admin` เมื่อไม่มี `playbook_id`; ใน Phase 2 เดิม `websocket.py` จำกัด `/ws/analysis/*` เป็น `SOC Analyst Tier 1-2`/`admin` และ `/ws/agent/*` เป็น `Threat Hunter`/`admin`, จากนั้น Phase 2.5 ขยาย `/ws/analysis/*` เป็นทุก authenticated role และคง `/ws/agent/*` ตามเดิมพร้อม owner check

**Known gap ที่ปิดแล้วใน Phase 2.5:** `GET /api/chat/sessions` และ `GET /api/chat/sessions/{id}` ไม่เป็น `admin-only` อีกต่อไป แต่ใช้ owner filter; `/ws/agent/{session_id}` ใช้ owner check เช่นเดียวกัน ส่วน legacy records ที่ `user_id = NULL` ให้ admin เห็นได้เท่านั้นใน owner-scoped paths

**หลักฐานการทดสอบ:** Phase 2 เดิมมี `tests/test_rbac_middleware.py` จำนวน 107 cases และ regression suite รวม 119 passed; coverage และ known gap ที่เหลือถูกปิด/ขยายใน Phase 2.5

**ขอบเขตที่ดำเนินการ:** รวม `src/web/websocket.py` ในการบังคับ JWT และ role ผ่าน WebSocket ตามขอบเขตของ Phase 2

## D10.4 Phase 3 — Per-flow filtering

**Current implementation status (2026-09-17):** `[x]` D10.4 implemented in
commit `21225e9`; this entry is the documentation follow-up commit.

**Implementation evidence:** Centralized fail-closed allowlist policy and
serializers are in `src/web/visibility.py`. Response-boundary filtering is
wired into Analysis, Dashboard, Reports, Chat, Agent, Playbooks, Cases, and
WebSocket frames. Threat Hunter direct Playbook routes remain denied and are
available only through Flow B. Cases now require authentication/RBAC, with
Team Lead limited to read plus priority/assignee operations. MCP management
routes and MCP server code/configuration were intentionally excluded.

**Verification:** `.venv\\Scripts\\python.exe -m pytest -q --tb=short
--basetemp .pytest-tmp-d10-4-final` → `1,587 passed, 12 warnings, 8
subtests passed`.

**วัตถุประสงค์:** ทำให้ข้อมูลและ flow ที่แต่ละ role เห็นแตกต่างกันตาม requirement

**วิธีทำ:** กำหนด field/data visibility ต่อ role และใช้ filtering ในแต่ละ flow หลัง RBAC middleware พร้อมใช้งาน

**ทำเพื่ออะไร:** ให้ role ไม่ได้เพียง login ได้/ไม่ได้ แต่เห็นข้อมูลตามหน้าที่จริง

**ผลลัพธ์ที่ต้องได้:** SOC Analyst เห็น Flow A แบบ trim raw source field; Incident Responder ผูกกับ playbook approval gate; Threat Hunter เห็น Flow B เต็ม

**สถานะ:** `[x]` เสร็จแล้วใน commit `21225e9`; implementation และ tests
อยู่ใน commit ชุดแรก และ entry นี้เป็น documentation follow-up.

## CV Readiness Investigation (2026-09-15; historical snapshot, superseded)

**Current-state note:** The investigation below records the pre-AHP readiness
state. It is preserved for provenance, but its legacy tier counts and open
decision do not describe the current production implementation. The current
production source admission and multipliers are defined in the current-session
section at the top; the later exploratory artifact remains
`preliminary_signal_only`.

**Historical status:** At the time of this note, CV had never successfully run. Code existed as a 5-fold
`StratifiedKFold` implementation at `scripts/eval/fit_source_weights.py:219`,
but no persisted CV output artifact was found.

- **Tier assignment:** the hardcoded scoring tiers are present in
  `src/scoring/intelligent_scoring.py`: high `=1.5` (5 sources), medium
  `=1.0` (14 sources), and low `=0.5` (4 sources). The cache currently contains
  26 distinct source names; the explicit tier lists contain 23 sources. The
  assignment has not yet been empirically validated by CV. `ip2proxy`,
  `threatzone`, `triage`, and `usom` are marked temporary pending weight-fitting.
- **`eval_results_group_a_v2.CONTAMINATED.jsonl`:** the root cause of the
  `CONTAMINATED` label was not found in repository history or commit messages.
  The file is untracked, gitignored, and has no file history. Its contents are
  structurally clean (408 unique IOCs, no duplicates, no errors, all matching
  the benchmark), but it must not be used as canonical CV input without knowing
  why it was flagged. Do not re-investigate that label; the recorded decision
  is to build a fresh canonical result via `scripts/eval/eval_benchmark.py`.
- **Benchmark dataset:** `data/benchmark/benchmark_iocs_v2.json` was confirmed
  at 894 records (`MALICIOUS=709`, `CLEAN=185`). Its schema is a JSON array,
  not JSONL.
- **Cache coverage:** 459/894 IOCs (51%) currently have telemetry in
  `C:\Users\ACER\.blue-team-assistant\cache\ioc_cache.db`; 435 IOCs are
  missing. The estimated additional calls to fill the current applicable
  26-source cache universe are approximately 4,168:

  | IOC type | Missing IOCs | Additional source-calls |
  |---|---:|---:|
  | domain | 207 | 1,863 |
  | ip | 65 | 1,040 |
  | md5 | 66 | 528 |
  | sha256 | 58 | 464 |
  | url | 39 | 273 |
  | **Total** | **435** | **4,168** |

  Missing provenance counts are `threatfox=161`, `circl_misp_feed_osint=124`,
  `tranco_top_sites=95`, `malwarebazaar_recent_detections=51`, and
  `manual_known_good=4`.
- **Conversion path:** `scripts/eval/eval_benchmark.py` converts the benchmark
  JSON into the eval JSONL format expected by `fit_source_weights.py` and
  supports `--resume`.
- **Partial-cache behavior:** `fit_source_weights.py` can run with partial
  cache coverage because missing source rows become score `0` in
  `build_feature_matrix()`. This introduces missingness bias and is not a
  full-coverage CV result.

**Historical open decision:** whether to fill the then-missing IOCs or run CV
on partial coverage. This was later resolved by producing the persisted
exploratory six-source artifact; it remains non-production evidence and does
not supersede the accepted AHP derivation.

### 2026-09-15 Session Summary — Talos exclusion, reliability windows,
### Group A CV pipeline prep

**1. Talos excluded from scoring (commit 060e9a6)**
- Root cause: `120/120` fail across window1 (`60/60`) — DNS SenderBase timeout
  approximately `5s`, matching the configured timeout; service deprecated per
  source code comment.
- Removed from: `intelligent_scoring.py` `medium_confidence_sources` and
  `scripts/eval/fit_source_weights.py` source list.
- Test updated: `test_threat_intel_source_accounting.py` — `talos` added to
  `UNTIERED_SOURCES` (integration code retained, scoring tier removed).
- Verified: grep `talos` in both target files has no active reference; 26 tests
  passed.

**2. Reliability window collection — 3 of 3 complete**
- Window1 (`12:21–12:35 UTC+7`): `3,365` rows, talos-excluded via retroactive
  filter, 13 effective sources, validated clean single-window sequence.
- Window2 first attempt: **INVALID** — quarantined to
  `evidence/reliability_sampling/invalid_runs/window2_2026-09-15_ENV_BLOCK_INVALID.jsonl`.
  Root cause: stale Codex sandbox firewall rules
  (`codex_sandbox_offline_block_*`) blocking outbound HTTPS at the local socket
  layer. Manually removed via `Remove-NetFirewallRule`; confirmed fixed via
  direct curl test (`200 OK`).
- Window2 second attempt: crashed on `tor_exit_nodes` transient timeout
  ("semaphore timeout period expired") before writing output — non-retry per
  protocol, no data produced; connectivity was re-confirmed healthy afterward.
- Window2 third attempt: **SUCCESS** — `09:45:45–09:58:08 UTC` (`743.3s`),
  `3,125` rows, 100% success across all `1,205` executable rows, 13 sources,
  no talos, zero `other(error)` failures.
- Window3: **SUCCESS** — `12:14:16.851–12:24:12.109 UTC` (`595.3s`),
  `3,125` rows, `1,205/1,205` executable rows succeeded, 13 sources, no
  talos, zero failures across all error types.
- Effective valid dataset for reliability metrics: window1 (talos-filtered),
  window2 (clean), and window3 (clean); `3/3` valid windows complete.

**3. Group-A-only CV data collection pipeline (commit d9daa51)**
- Problem discovered: `eval_benchmark.py` called all sources, including Group B
  (`alienvault`, `virustotal`, `shodan`, etc.) and talos; no allowlist mechanism
  existed.
- Fix: threaded optional `allowed_sources` through three layers:
  - `ThreatIntelligence.investigate_ioc_comprehensive()` filters before task
    creation, so disallowed sources make no network call and are not merely
    filtered post-hoc.
  - `IOCInvestigator.investigate()` forwards the allowlist.
  - `eval_benchmark.py` adds `--group-a-only`, using the locked 7-source
    allowlist: `feodotracker`, `tor_exit_nodes`, `c2_trackers`, `usom`,
    `sslblacklist`, `spamhaus`, `circl`.
- Default behavior (`allowed_sources=None`) is unchanged and backward
  compatible; production scoring is unaffected.
- New tests confirm Group B sources receive `assert_not_awaited()` when the
  allowlist is active; 66 tests passed in total.

**4. CV readiness — dry run complete, cache write bug found and fixed**
- Dry run: `eval_benchmark.py --group-a-only --malicious-limit 1 --delay 0`
  processed all 186 CLEAN-included IOCs (`--malicious-limit` does not limit
  CLEAN count — known script limitation) in `1,289.7s` (`6.934s/IOC` average),
  exit 0, 0 errors, and 0 malformed rows. Output:
  `scripts/eval/eval_results_group_a_v2.jsonl` (`186` rows).
- **Bug found:** cache writes silently failed (`attempt to write a readonly
  database`) during the dry run. The cache remained at `3,256` rows, so the
  dry run produced label data but did not populate `ioc_cache.db`.
- Root cause: ACL on
  `C:\Users\ACER\.blue-team-assistant\cache` — `CodexSandboxUsers` had
  Read/Execute only, not Modify. This was not a code bug, not a file
  read-only attribute, and not a stale lock.
- **Fixed:** granted Modify ACL to `CodexSandboxUsers` on the cache directory
  and `ioc_cache.db`. Verified with a probe write (`3,256 → 3,257 → cleanup
  to 3,256`).
- **Status:** cache write is confirmed working. Ready to run the full
  `--resume` batch to fill remaining IOCs toward the 894 target; **NOT YET RUN**
  (deferred until after reliability collection to avoid concurrent
  cache/network load).

**5. Unrelated discovery (not part of this session's scope, informational only)**
- `evidence/MISP_live_feed_inspect/` contains a read-only MISP CIRCL live-feed
  audit (manifest plus 29-event bounded sample, 100% success, all 4 IOC types
  present). Status is explicitly provisional/untiered — not a scoring decision.
  Origin appears to be an earlier/parallel session working the
  "MISP/CIRCL implementation not yet started" backlog item. No code was
  changed by this audit.

**OPEN ITEMS / NEXT STEPS**
- Run `eval_benchmark.py --group-a-only --resume` to fill remaining IOCs
  toward full 894-IOC coverage (approximately 80–90 minutes estimated).
- After cache reaches full/near-full coverage, run `fit_source_weights.py`
  5-fold CV — this has **never successfully run**; no persisted output exists
  as of this note.
- Build the reliability metrics table from the three valid windows (window1
  talos-filtered + window2 + window3); no aggregation script exists yet and
  one needs to be written.
- `eval_results_group_a_v2.CONTAMINATED.jsonl` root cause remains unknown
  (untracked, no git history). The decision is not to reuse it; build fresh
  canonical results via `eval_benchmark.py` instead.

### 2026-09-15 Follow-up — CV artifact and Feodo/Tor integration validation

**1. CV source policy committed (commit `af7812a`)**
- `scripts/eval/fit_source_weights.py` now applies a validated Group-A CV
  allowlist: `feodotracker`, `tor_exit_nodes`, `spamhaus`, and `c2_trackers`.
- Group-B sources and the currently unvalidated/problematic Group-A sources are
  excluded from the exploratory fit. Excluded sources are reported with reasons:
  `circl` (endpoint returned 404/401 and Passive DNS access is restricted),
  `sslblacklist` (IP feed deprecated), and `usom` (pagination/content
  validation incomplete).
- This policy is local to the analysis script; production scoring tiers and
  source defaults were not changed.

**2. CV artifact output and first 5-fold run**
- `fit_source_weights.py` was extended to write a structured JSON artifact at
  `scripts/eval/fit_source_weights_results.json`, including UTC timestamp,
  dataset/cache provenance, selected/excluded sources, per-source coverage,
  coefficients, fold metrics, and limitations. It supports `--output` for a
  custom artifact path.
- CV completed successfully with exit code `0` on all `894` IOC records
  (`MALICIOUS=709`, `CLEAN=185`). The artifact status is explicitly
  `preliminary_signal_only`; it must not replace production weights.
- Selected source coverage in the inferred latest cache round:
  `c2_trackers=487/894 (54.47%)`, `feodotracker=151/894 (16.89%)`,
  `spamhaus=151/894 (16.89%)`, and `tor_exit_nodes=150/894 (16.78%)`.
  The low coverage is partly source applicability (the latter three are
  IPv4-oriented), and missing rows are still represented as score `0`.
- Mean coefficients: `spamhaus=1.0571`, `c2_trackers=0.2049`,
  `feodotracker=0.0`, `tor_exit_nodes=0.0`. Mean 5-fold metrics were
  accuracy `0.2629`, precision `1.0000`, recall `0.0705`. These results show
  a weak/imbalanced preliminary signal, not deployable weights.
- The artifact-writer changes and the generated CV artifact were intentionally
  left uncommitted at this ledger update; only the prior CV policy commit is
  committed. Existing eval JSONL and unrelated evidence remain untouched.

**3. FeodoTracker/Tor positive-control validation (commit `875cb8e`)**
- Current live feeds responded successfully: Feodo `ipblocklist.json` HTTP
  `200` with `5` IPv4 entries; Tor `torbulkexitlist` HTTP `200` with `1,344`
  IPv4 entries at validation time.
- Direct integration positive controls passed:
  - Feodo `162.243.103.246`: `found=True`, flagged, score `95`.
  - Tor `171.25.193.25`: `found=True`, flagged, score `30`.
- Negative control `198.18.0.1` returned `found=False`, score `0` for both.
- The integration now returns an explicit `found` field for these sources, and
  Tor matching uses exact feed lines instead of substring matching. Fixtures
  and unit tests were added; the relevant test set passed (`31 passed`).
- Benchmark-only coverage report:
  `evidence/source_telemetry_2026-09-15/feodo_tor_benchmark_coverage_2026-09-15.json`.
  It records Feodo `154/154` applicable IP cache rows with `0` matches and
  Tor `153/154` with `0` matches. Domain, URL, MD5, and SHA256 are
  non-applicable and were excluded from the denominator.
- Conclusion: both integrations are functioning, but the benchmark has no
  overlap with the current Feodo/Tor feeds. Do not set their production
  weights to zero or treat no-match as CLEAN. Do not rerun CV for these two
  sources until source-specific positive-control data is included.

**4. Cache write investigation during live validation**
- A normal sandbox-process probe could read
  `C:\Users\ACER\.blue-team-assistant\cache\ioc_cache.db` but failed to write
  with `OperationalError: attempt to write a readonly database`.
- No `.db-wal` or `.db-shm` files were present; the database file was not
  marked read-only. The failure is an execution-environment/ACL boundary,
  not a Feodo/Tor parser failure and not a SQLite stale-lock condition.
- The same live comprehensive calls were rerun with the required write
  permission: cache rows increased `3901 -> 3903`, and both Feodo/Tor rows
  were verified with current `queried_at` timestamps and flagged results.
- Future cache collection must run under an identity with Modify permission
  on the cache directory/database; a read-only sandbox process is not a valid
  cache-write validation environment.

**5. vLLM virtual-key issue (informational; no fallback added)**
- During eval, vLLM returned HTTP `403` with `virtual_key_blocked` / `Virtual
  key is inactive`. The call path is `LLMAnalyzer._call_vllm_api()`; each IOC
  can produce two non-retry calls (IOC analysis and FortiGate translation).
- The eval JSONL records only scoring fields and remained structurally valid;
  the LLM enrichment failure was non-fatal and did not affect verdict,
  threat score, or source accounting.
- `/v1/models` exposed `12` model IDs, but changing models with the same
  inactive key is not a fix. No fallback model was added; key activation or
  disabling LLM enrichment for eval is the correct next decision.

**OPEN ITEMS / NEXT STEPS**
- Commit or review the currently uncommitted CV artifact-writer changes and
  generated artifact policy before treating the CV result as reproducible.
- Fix and validate `circl`, `sslblacklist`, and `usom` separately; collect
  source-specific positive controls before including them in a future CV run.
- Build the reliability aggregation table from the three valid windows
  (window1 talos-filtered + window2 + window3); no aggregation script exists
  yet.
- Keep Feodo/Tor in production tiers, but interpret their benchmark zero-match
  result as dataset non-overlap rather than integration failure.

### 2026-09-15 Follow-up — targeted source recollection and six-source CV

**1. Follow-up commits recorded**
- `8475992` — persist exploratory CV results artifact.
- `651067a` — fix CIRCL, SSLBL, and USOM feed validation.
- `8ffe764` — remove obsolete USOM bulk feed fallback.
- `1fed8c5` — expand the exploratory CV allowlist to six sources and mark
  CIRCL as a permanent exclusion.
- `ebd0218` — select the latest cache row per `(IOC, source)` across the mixed
  collection window and distinguish unavailable/error rows from valid evidence.
- `a33f1b2` — correct the CV adequacy limitation output so the EPV comparison
  reflects the measured value.

**2. Targeted SSLBL/USOM recollection**
- Scope: the 894-record evaluation set; executable target was 154 IPv4 IOCs.
- Only `sslblacklist` and `usom` made source calls. No full benchmark,
  reliability window, or `eval_benchmark` batch was rerun.
- Prechecks passed: ledger read, no stale cache lock/WAL/SHM, no evaluation
  process left running, and the cache identity had Modify permission.
- SSLBL: `154/154` rows refreshed as unavailable/deprecated warnings;
  `0` valid matches; stale rows were explicitly overwritten as unavailable.
- USOM: `154/154` rows refreshed, `147` not found, `7` exact matches, and
  `0` errors. Exact matches were:
  `104.194.159.150`, `107.189.26.194`, `213.145.86.112`,
  `31.57.243.154`, `38.146.28.132`, `38.146.28.75`, and
  `91.215.85.103`.
- Cache verification after recollection: SSLBL `154` rows with status warning
  and `found=0`; USOM `154` rows with `7` found and `147` not found.

**3. CIRCL status**
- The Passive DNS endpoint and NDJSON parsing are corrected, but the endpoint
  returns HTTP `401` because partner authorization is required and is not
  available in this environment.
- CIRCL is therefore **excluded permanently**, not pending repair, with the
  same status as GreyNoise/Pulsedive:
  `CIRCL Passive DNS requires partner authorization not available in this
  environment; excluded permanently, same status as GreyNoise/Pulsedive`.

**4. Six-source exploratory CV**
- Artifact: `scripts/eval/fit_source_weights_results_6source.json`.
- Status: `preliminary_signal_only`; production scoring tiers were not changed.
- Dataset: `894` rows (`MALICIOUS=709`, `CLEAN=185`). Cache selection mode:
  `latest_row_per_ioc_source_mixed_window`.
- Valid coverage: `c2_trackers=573/894 (64.09%)`,
  `feodotracker=154/894 (17.23%)`, `spamhaus=154/894 (17.23%)`,
  `tor_exit_nodes=153/894 (17.11%)`, `usom=154/894 (17.23%)`, and
  `sslblacklist=0/894 valid; 154 unavailable`.
- Mean standardized coefficients:
  `spamhaus=1.053918`, `usom=0.395077`, `c2_trackers=0.200997`,
  `feodotracker=0`, `tor_exit_nodes=0`, and `sslblacklist=0`.
- Five-fold CV mean metrics: accuracy `0.269594`, precision `1.000000`,
  recall `0.079013`; standard deviations were `0.013818`, `0`, and `0.017020`.
- EPV: `30.833333` minority events per six source features; both 10-EPV and
  20-EPV checks passed, but EPV alone does not establish adequacy.
- `c2_trackers` and `usom` were fold-sensitive by the configured rule.
  High- and low-tier refit features were constant because the selected data
  had no usable high/low-tier score variation; tier ranking agreement was
  `0/5` for both sum and max aggregation.
- Interpretation: zero Feodo/Tor coefficients reflect no benchmark overlap,
  not zero production reliability; SSLBL has no valid observation and its
  coefficient is not evidence of low reliability. Further source-specific
  positive controls, held-out validation, calibration, and reliability
  aggregation are required before any production weight change.

**5. Current next action**
- Keep the six-source output as exploratory evidence only.
- Add source-specific positive controls to the validation design, then perform
  held-out validation/calibration and aggregate the three valid reliability
  windows. Do not modify production scoring tiers until those gates pass.

### 2026-09-15 Follow-up — source-specific controls and internal holdout validation

**1. Source-specific live controls**
- Evidence: `evidence/source_telemetry_2026-09-15/source_positive_controls_2026-09-15.json`.
- Controls were run separately from the 894-record benchmark and did not write
  to `ioc_cache.db`.
- FeodoTracker feed: HTTP `200`, `5` entries / `5` usable IPs. Positive
  `162.243.103.246` returned `found=true`, botnet `Emotet`, score `95`;
  negative `198.18.0.1` returned `found=false`, score `0`.
- Tor exit feed: HTTP `200`, `1,343` usable IPs. Positive `171.25.193.25`
  returned `found=true`, `is_tor=true`, score `30`; negative `198.18.0.1`
  returned `found=false`, `is_tor=false`, score `0`.
- SSLBL certificate feed: `10,715` SHA1 entries; IP feed has `0` entries and
  is marked deprecated. Positive SHA1
  `00095e3cd5dfc929d16036132665d7e3e9ef7cd6` returned `found=true`, score
  `90`; all-zero SHA1 negative returned `found=false`, score `0`.
- All six positive/negative control assertions passed. These controls validate
  integration behavior and are not added as benchmark labels for model fitting.

**2. Internal held-out validation and calibration**
- Evidence: `evidence/source_telemetry_2026-09-15/source_weights_holdout_6source_2026-09-15.json`.
- Split: train `536` (`111` clean, `425` malicious), calibration `179`
  (`37` clean, `142` malicious), untouched test `179` (`37` clean,
  `142` malicious), random state `20260915`.
- Raw logistic test metrics: accuracy `0.312849`, precision `1.000000`,
  recall `0.133803`, ROC-AUC `0.566901`, Brier `0.232308`, log loss
  `0.638464`, predicted positives `19/179`.
- Platt-calibrated test metrics: accuracy `0.793296`, precision `0.793296`,
  recall `1.000000`, ROC-AUC `0.566901`, Brier `0.162226`, log loss
  `0.503777`, predicted positives `179/179`.
- Calibration did not improve discrimination and produced an all-positive
  threshold decision. This is an internal holdout from the same labelled
  dataset, not an independent external validation set.
- **Decision:** source-specific controls pass, but held-out/calibration gate
  does not pass for production use. Keep all CV coefficients and calibration
  results as exploratory evidence only; do not change production weights or
  scoring tiers.

**3. Next validation requirement**
- Obtain an independent labelled holdout with sufficient source overlap,
  including Feodo/Tor positives and SSLBL SHA1-compatible records, then repeat
  fit, calibration, and shadow comparison before any production change.

### 2026-09-16 Follow-up — three-window reliability aggregation

**1. Reproducible aggregation**
- Script and tests: `scripts/eval/aggregate_reliability_windows.py` and
  `tests/test_aggregate_reliability_windows.py` (commit `a1edabf`).
- Artifact: `evidence/reliability_sampling/reliability_aggregation_2026-09-15.json`.
- The script read only the preserved valid window files; it made no network
  calls and did not modify the raw JSONL windows.
- Regression result: `3 passed`; the only warning was the existing pytest
  cache-path warning from the execution environment.

**2. Aggregate result**
- Window1: `3,365` raw rows; `1,205` executable rows after excluding Talos.
- Window2: `3,125` raw rows; `1,205` executable rows.
- Window3: `3,125` raw rows; `1,205` executable rows.
- Historical aggregate after Talos exclusion: `9,375` rows,
  `3,615` executable, `3,614` success, `1` failure, success rate
  `99.972337%`, failure rate `0.027663%`.
- The one failure was `malwarebazaar` with error type `5xx` in window1;
  windows2 and 3 had no executable failures.
- Overall latency was retained by class rather than ranked across classes:
  `api_request` n=`2,160`, `cold_refresh` n=`15`,
  `uncached_feed_request` n=`360`, and `warm_cached_lookup` n=`1,080`.

**3. Source consistency and policy interpretation**
- All non-Talos sources had `100%` executable-count consistency across the
  three windows. `malwarebazaar` was the only source with a failure:
  `179/180` successes (`99.444444%`).
- Talos raw historical metrics remain visible (`60` executable failures) but
  are excluded from the aggregate under commit `060e9a6`.
- CIRCL historical rows show successful completion in these older windows,
  but are retained for audit only and excluded from the current eligible set
  because current Passive DNS access requires unavailable partner authorization.
- Operational success means the call completed; it does not establish source
  detection correctness. Found counts are not ground truth and must not be
  converted directly into production weights.

**4. Current status**
- The three-window aggregation is complete as historical operational evidence,
  but it is not the locked seven-day/21-window protocol. Independent labelled
  holdout, source-overlap controls, calibration, and shadow comparison remain
  required before changing production scoring tiers or weights.

### 2026-09-16 Follow-up — independent labelled holdout preparation

**1. Holdout design**
- Specification: `docs/independent_labelled_holdout_spec.md`.
- The proposed panel is `240` records with balanced labels: `120` independent
  `MALICIOUS` and `120` documented-as-clean records.
- Planned strata are `60/60` IPv4, `30/30` SHA1 certificate hashes, and
  `30/30` domains. The IPv4 panel must provide overlap checks for FeodoTracker,
  Tor exit nodes, Spamhaus, C2 Trackers, and USOM; the SHA1 panel must check
  SSLBL certificate-feed overlap; the domain panel must check USOM and C2
  Trackers overlap.
- Label provenance is explicitly separate from target-source results. A
  target source's `found=false` response is not accepted as a `CLEAN` label.
  The final manifest must retain provider, evidence reference, confirmation
  date, rationale, collection timestamp, and disjointness metadata.

**2. Readiness audit**
- Evidence: `evidence/source_weights_2026-09-16/independent_holdout_readiness_2026-09-16.json`.
- Status: `not_ready_for_weight_fit`. No final holdout record set was created
  or used for fitting.
- The existing reliability sample is balanced but is not independent: `150/240`
  records derive from `benchmark_iocs_v2`. The source positive controls are
  integration controls only, and the bounded MISP audit did not persist IOC
  values. The current `894`-record Group-A evaluation and all derived cache
  rows remain disjoint by policy.
- The latest observed FeodoTracker snapshot had only `5` usable IP entries,
  so the proposed `30`-positive Feodo panel cannot be claimed from that
  snapshot. Tor, SSLBL SHA1, USOM, Spamhaus, and C2 overlap are likewise not
  verified until independently labelled records are acquired.

**3. Decision and next gate**
- This step prepared the design and machine-readable readiness gates only; it
  did not authorize a new CV run or production scoring change.
- Before weight fitting, acquire and persist independent malicious evidence
  (event/provider references and dates), independently documented clean
  candidates, verify disjointness against Group A, run target-source overlap
  checks, and freeze the labelled manifest. Then perform independent holdout
  fit/calibration and shadow comparison.

### 2026-09-16 Follow-up — public-data proxy holdout and overlap gate

**1. Frozen public-data manifest**
- Preparation script: `scripts/eval/prepare_independent_proxy_holdout.py`.
- Frozen manifest: `evidence/source_weights_2026-09-16/independent_external_proxy_holdout_2026-09-16.json`.
- The manifest contains `240` unique records with balanced labels (`120`
  `MALICIOUS`, `120` `CLEAN`) and balanced types: IP `60/60`, domain `30/30`,
  and SHA1 `30/30`. It passed required-field, uniqueness, and Group-A
  disjointness checks.
- Malicious evidence came from ThreatFox (IP) and PhishTank (domains and
  observed TLS certificate associations). Clean records are explicitly marked
  `label_quality=proxy`, derived from Cloudflare ranking plus public DNS/TLS
  observations; they are not absolute clean ground truth.
- The frozen manifest SHA-256 is recorded in the overlap artifact. Its target
  source overlap fields were null before collection and were not used as labels.

**2. Target-source overlap collection**
- Runner: `scripts/eval/collect_holdout_source_overlap.py`.
- Result: `evidence/source_weights_2026-09-16/independent_external_proxy_holdout_overlap_2026-09-16.json`.
- Raw responses: `evidence/source_weights_2026-09-16/holdout_overlap_raw_2026-09-16/`.
- FeodoTracker: HTTP `200`, `5` usable current entries, `0/120` holdout hits.
- Tor exit nodes: HTTP `200`, `1,342` usable entries, `0/120` holdout hits.
- SSLBL: certificate feed was available but had `0/60` holdout SHA1 hits;
  IP feed returned HTTP `200` but is deprecated, so `120` IP checks are
  unavailable rather than negative.
- USOM: `180` exact-match requests, `0` hits and `1` error. Spamhaus returned
  `18/120` hits (`17` malicious-label records, `1` clean-proxy record).
  C2 Trackers returned `7/180` hits, all on malicious-label records; only one
  of ten configured C2 snapshots returned HTTP `200` and nine returned `404`.

**3. Gate decision**
- Gate report: `evidence/source_weights_2026-09-16/independent_holdout_gate_report_2026-09-16.json`.
- **Decision:** do not run a new CV fit from this holdout and do not change
  production weights. The panel is balanced and reproducible, but its clean
  labels are proxies and the required Feodo/Tor/SSLBL/USOM positive overlap
  gates did not pass. The artifact is therefore a public-data coverage/proxy
  pilot, not an adequate independent weight-validation set.
- The raw overlap responses are retained for audit. No reliability windows,
  full benchmark, production scoring code, or prior artifacts were rerun or
  overwritten.

### 2026-09-16 Follow-up — deadline tier policy freeze (historical, superseded)

**1. Decision scope**
- Policy document: `docs/source_tier_policy_decision_2026-09-16.md`.
- Machine-readable decision: `evidence/source_weights_2026-09-16/source_tier_policy_decision_2026-09-16.json`.
- This section records the pre-AHP deadline snapshot. At that point the
  decision froze the existing nominal production multipliers without changing
  `src/scoring/intelligent_scoring.py`: High `1.5`, Medium `1.0`, Low `0.5`,
  and unknown/untiered fallback `0.8`. It is superseded by the current-session
  AHP amendment at the top of this ledger.
- The existing Group-B exclusion boundary is unchanged. A source may retain a
  nominal legacy tier for backward compatibility while remaining supplemental
  or excluded from the critical aggregate.

**2. Tier assignment retained**
- High: `virustotal`, `abuseipdb`, `feodotracker`, `threatfox`,
  `malwarebazaar`.
- Medium: `alienvault`, `urlhaus`, `c2_trackers`, `greynoise`, `shodan`,
  `criminalip`, `ipqualityscore`, `spamhaus`, `pulsedive`, `censys`,
  `ip2proxy`, `threatzone`, `triage`, `usom`.
- Low/context: `tor_exit_nodes`, `circl`, `phishtank`, `sslblacklist`.
- Untiered fallback: `smet_nrd`, `hagezi_nrd`, `mb_recent_sha256`,
  `misp_circl_feed_osint`, `talos`, and unknown sources.
- CIRCL remains permanently excluded from CV eligibility due unavailable
  partner authorization; its nominal legacy Low mapping remains unchanged to
  preserve production behavior.

**3. Verification and final status**
- Targeted regression tests: `22 passed`, one existing pytest cache-path
  warning from the environment.
- `git diff --quiet -- src/scoring/intelligent_scoring.py`: pass; production
  scoring code is unchanged.
- Learned coefficients remain `preliminary_signal_only`; no coefficient was
  promoted into a production multiplier.
- **Historical decision:** tier policy was considered complete and frozen for
  the deadline deliverable at that snapshot. The current AHP-derived
  multipliers and six-source admission policy are recorded in the current
  session section at the top of this ledger.

## D10.5 Phase 4 — Gmail OAuth (per-user)

**วัตถุประสงค์:** ผูก Gmail ของ user แต่ละคนเข้ากับระบบแจ้งเตือน

**วิธีทำ:** ใช้ OAuth2 Authorization Code flow ต่อ user และเก็บ refresh token แบบ encrypted

**ทำเพื่ออะไร:** ให้ระบบส่ง notification โดยอ้างอิง Gmail ที่ user คนนั้นอนุญาต แทนการมี recipient เดียวแบบ static

**ผลลัพธ์ที่ต้องได้:** user แต่ละคนสามารถ authorize Gmail ของตนเอง และระบบใช้ credential ต่อ user ได้

### Phase 4 pre-implementation setup — DONE โดยผู้ใช้

**สถานะปัจจุบัน (2026-09-17):** `[~]` Google Cloud-side setup เสร็จแล้ว และพร้อมสำหรับการทำ implementation; ส่วน Phase 4 implementation ยังไม่เริ่ม

ตาม user confirmation:

- มี Google Cloud Project และเปิดใช้งาน Gmail API แล้ว
- ตั้งค่า OAuth Consent Screen เป็น `External` แล้ว
- สร้าง OAuth Client ประเภท `Web application` แล้ว
- ลงทะเบียน Redirect URI: `http://localhost:3003/api/settings/gmail/callback` ซึ่งตรงกับ local dev port ใน README
- ตั้งค่า Client ID และ Client Secret เป็น persistent Windows User environment variables: `GMAIL_OAUTH_CLIENT_ID` และ `GMAIL_OAUTH_CLIENT_SECRET`
- ยืนยันการทำงานจาก terminal ใหม่หลัง activate `D:/ai_cti_automate/.venv/Scripts/Activate.ps1`

**Decisions ที่บันทึกไว้สำหรับ implementation:**

- owner-only: ผู้ใช้ผูก/ถอดผูกได้เฉพาะ Gmail ของตนเอง และทั้ง 5 roles สามารถ connect ได้
- ใช้ scopes เฉพาะ `gmail.send` และ identity scopes; ไม่ขอสิทธิ์อ่านหรือแก้ไข mailbox
- ใช้ SQLite OAuth-state table สำหรับผูก callback กับผู้ใช้และป้องกัน CSRF/state replay
- ใช้ environment variables สำหรับ OAuth client secrets และ MultiFernet สำหรับ token encryption
- เมื่อ disconnect ให้ hard-delete token แต่เก็บ audit record ไว้

**ขั้นถัดไปที่อยู่ในคิว (ยังไม่เริ่ม):** สร้าง `007_add_user_gmail_tokens.py`, token storage/encryption, routes `/api/settings/gmail/connect`, `/callback`, `/status`, `DELETE` และ Settings UI card ตาม diff plan ที่รออนุมัติ

**ข้อจำกัด:** การบันทึกนี้ไม่ถือเป็นการทำ Gmail OAuth implementation เสร็จสมบูรณ์ และยังไม่มีการแก้โค้ด สร้าง migration หรือ commit ในขั้นตอนนี้; ห้ามแตะ `smtp_*` เดิมและ MCP Server

**ขอบเขตที่ต้องปลดล็อก:** ต้อง lift config scope สำหรับ `config.yaml` เฉพาะ section ใหม่ ห้ามแตะ `smtp_*` เดิม

## D10.8 Phase 6 — Team Lead role addition

**หลักการออกแบบ:** `Team Lead` แยกจาก `admin` โดยเด็ดขาด และออกแบบเป็น
SOC scope เดิมบวก explicit allowlist เพิ่มเติม ไม่ใช่ admin ที่ถูกตัดสิทธิ์บางส่วน
เพื่อป้องกัน privilege leak และทำให้สิทธิ์ที่เพิ่มตรวจสอบได้เป็นรายการ

**สิทธิ์ที่เพิ่มจาก SOC Analyst Tier 1-2:**

- อ่าน Flow A analysis ของ SOC analyst ทุกคนแบบ cross-user ผ่าน serializer/trim
  level เดียวกับ SOC ไม่ใช่ raw result
- เห็น dashboard recent ของทุกทีม
- อ่าน sanitized reports ในระดับเดียวกับ SOC/Incident Responder
- escalate/reassign case และเปลี่ยน priority
- approve detection rule เพิ่มเติมจาก (ไม่แทนที่) สิทธิ์ของ Incident Responder/admin

**สิทธิ์ที่ไม่ได้รับ:**

- ไม่ใช่ admin เต็มรูปแบบ: ห้าม invite user, แก้ system/notification config หรือดู
  system-level audit log
- ไม่เข้าถึง `/api/chat` (Flow B) ด้วยเหตุผลเดียวกับ SOC
- ไม่ได้ raw data มากกว่า SOC serializer
- ไม่เรียก dangerous tools เช่น sandbox, isolate, block หรือ quarantine

**Audit และ migration constraints:**

- ทุก cross-user read ต้องมี audit log แยกจาก normal owner-read
- Role นี้ต้องใช้ additive migration ใหม่เท่านั้น ห้ามแก้ migration เดิม
- ไม่มี user ได้ role `Team Lead` โดยอัตโนมัติ
- Test negative case (Team Lead เรียก admin-only endpoint → `403`) ต้องมาก่อน
  positive-case tests

**Evidence จาก investigation ก่อนหน้า:** มี schema/migration impact จากการเพิ่ม role,
audit-log gap สำหรับ cross-user read และ serializer/visibility gap ที่ต้องปิดก่อน
implementation; รายละเอียดเต็มอยู่ในผล investigation เดิม ไม่ใช่การอนุมัติให้
แก้ schema หรือ code ในรอบนี้

**สถานะ:** `[x]` Team Lead Phase 1–3 เสร็จแล้ว

**Implementation evidence:** commit `e6c72d6 Implement Team Lead oversight and case operations`

- Phase 1: เพิ่ม `Team Lead` role, additive role migration และ negative RBAC tests
- Phase 2: เพิ่ม cross-user audit fields/logging, trimmed serializer และ implicit
  single-team read access สำหรับ Analysis/Dashboard
- Phase 3: เพิ่ม `assignee`/`priority` migration, Team Lead case reassignment/
  escalation และ rule approval โดยคง raw rule edit, dangerous tools, Flow B และ
  Admin endpoints ไว้ในขอบเขตเดิม
- Verification: full test suite บนเครื่องจริง `1,573 passed`, ไม่มี error/failure

**Scope note:** งานนี้ปิดเฉพาะ Team Lead Phase 1–3; generic D10.4 per-flow
filtering, Gmail OAuth และ notification routing by role ยังไม่ถือว่าปิด

**สถานะเดิมที่ถูกแทนที่:** ข้อความด้านล่างเป็น investigation note ก่อนเริ่ม
implementation และไม่ใช่ blocker อีกต่อไป:

1. SOC ควรเห็นเฉพาะข้อมูลของตัวเอง หรือคง shared behavior เดิมตามที่
   `docs/SOCPOW_scope_ledger.md:1164` ระบุอยู่ปัจจุบัน เพราะการเพิ่ม Team Lead กระทบ
   พฤติกรรมเดิมของ SOC role โดยตรง
2. คำว่า “SOC ในทีม” หมายถึงผู้ใช้ทุกคนที่มี role SOC ในระบบทั้งหมด หรือจะมี
   `team membership` concept แยกในอนาคต ปัจจุบันไม่มี `team_id` ใน DB
3. Endpoint ที่ยังไม่มี auth ตอนนี้ ได้แก่ `config_api.py`, `mcp_management.py` และ
   `cases.py` ควรแก้พร้อมกันหรือไม่ เพราะถ้าไม่แก้ ข้อกำหนดว่า Team Lead ไม่มี
   system access จะไม่เป็นจริงในทางปฏิบัติ

## D10.6 Phase 5 — Notification routing by role

**วัตถุประสงค์:** route notification ตาม role และ Gmail ที่ผูกไว้ต่อ user

**วิธีทำ:** ขยาย `NotificationManager.notify()` ให้ route ตาม role + Gmail ที่ผูกไว้จาก Phase 4 โดยเพิ่มจาก `to_addrs` static เดิม ไม่ใช่แทนที่

**ทำเพื่ออะไร:** ให้ notification ไปถึงผู้รับที่เกี่ยวข้องกับ role และ flow โดยยังคงรองรับ static recipient เดิม

**ผลลัพธ์ที่ต้องได้:** notification routing แยกตาม role/user ได้ และมี fallback/behavior ของ static `to_addrs` เดิมที่ตรวจสอบได้

**สถานะ:** `[ ]` ยังไม่เริ่ม

## D10.7 ลำดับงานที่ควรทำต่อ

1. `[x]` Phase 2 — RBAC middleware (เสร็จแล้ว)
2. `[x]` Phase 2.5 — Session ownership + analysis/report/dashboard auth (เสร็จแล้ว; legacy `NULL user_id` ใช้ admin-only policy เฉพาะ owner-scoped paths)
3. `[ ]` Phase 3 — Per-flow filtering
4. `[x]` D10.8 / Phase 6 — Team Lead role addition (Team Lead Phase 1–3 เสร็จแล้ว;
   implementation commit `e6c72d6`)
5. `[ ]` Phase 4 — Gmail OAuth
6. `[ ]` Phase 5 — Notification routing by role

## Weekly ritual (กันของหล่น)
1. ก่อนเริ่มแต่ละ session: เปิดไฟล์นี้ อัปเดต status เก่าก่อน แล้วค่อยเลือกงานถัดไป
2. ก่อนเริ่มแต่ละข้อ: เขียน DoD ใน column ให้ชัดก่อนสั่ง investigation prompt
3. จบแต่ละ session: อัปเดต status ทุกแถวที่แตะวันนี้ ห้ามปล่อยค้างเป็น 🔍 ข้ามคืนโดยไม่มี note
4. ก่อนพรีเซนต์: Section A ต้องไม่มีแถวไหนเป็น ⬜ — อย่างน้อยต้องเป็น 🔍 พร้อมคำตอบชั่วคราวที่มี evidence tier กำกับ

## Final domain-age/DGA scoring decision (16 Sep 2026)

**Decision log — commit `bb16056` (`Remove unjustified domain-age/DGA score bonuses from threat_score`).**

1. Multiple attempts were made to find a defensible magnitude, including a
   ThreatFox-based analysis and a Cisco Umbrella popularity cross-reference.
2. Both attempts exposed systematic selection bias, so the available data could
   not support a reliable estimate of the numeric magnitude.
3. The final decision was to remove all domain-age/DGA numeric bonuses. WHOIS
   domain-age and DGA pattern detection remain available as analyst-facing
   metadata, recommendations, and detection context only; they do not affect
   `threat_score` or `verdict`.
4. This decision is implemented in commit `bb16056`.

The detailed material below is retained as historical provenance and must not
be read as current production scoring behavior.

### Historical calibration evidence (not current scoring)

The expanded case-control set used all `4,737` unique ThreatFox domain IOCs
available after deduplication and static-benchmark overlap exclusion, plus a
`5,000`-domain Tranco clean proxy sample. The new WHOIS run wrote `9,737`
records. Of these, `8,513` lookups succeeded and `1,224` (`12.571%`) were
excluded because no usable creation date was returned or the lookup timed out.
The analysis therefore uses only successful WHOIS records: `3,949` malicious
and `4,564` clean.

| WHOIS age group | Malicious | Clean | Total | Malicious rate |
|---|---:|---:|---:|---:|
| Newly registered (`<30d`) | 79 | 6 | 85 | `0.9294117647058824` |
| Mature (`>=30d`) | 3,870 | 4,558 | 8,428 | `0.45918367346938777` |

The contingency table has no zero cell, so the reported odds ratio is the raw
cross-product ratio rather than a Haldane–Anscombe correction:

`OR = (79 * 4558) / (6 * 3870) = 15.507407407407408`.

The two-sided Fisher exact test gives
`p = 5.3127051808514964e-20`, which is significant at `alpha = 0.05` and
supports the intended direction: the newly-registered group has higher
malicious-label odds. The exact 95% confidence interval for its malicious rate
is `[0.8526665411514625, 0.973656069653473]`.

Compared with the previous case-control run, the newly-registered sample grew
from `n=6` to `n=85` (`+79`, or `14.166666666666666x`). The Fisher p-value
changed from `0.10975406052189701` to `5.3127051808514964e-20`. The exact
malicious-rate CI width narrowed from
`0.6370238344829999` to `0.1209895285020105`, a reduction of
`0.5160343059809894` (`81.0070641077026%`).

### Guard-free point-scale proposal

The previous adhoc guard that refused to propose a value when `OR > 10` was
disabled for this final calibration calculation. The mapping is unchanged:

1. Compute `log(OR)`; here `log(15.507407407407408) =
   2.7413178070207684`.
2. Normalize it as `100 * log(OR) / log(10)`, producing
   `119.05391967322431`.
3. Clamp the normalized value to `[0, 100]` and map linearly to the existing
   domain-enrichment budget `[0, 30]`.

The resulting historical proposed replacement was **`+30`**. The Wald 95% CI for the odds
ratio is `[6.754548482980063, 35.60262911803336]`; applying the same bounded
mapping gives a proposed-point 95% CI of
`[24.887889699613, 30.0]`. The upper endpoint saturates at `+30` because the
mapping is explicitly capped, not because the underlying odds-ratio interval
has an upper bound of 10.

### Final justification and limitations

The larger independent-label case-control run resolves the earlier low-power
problem: the newly-registered arm increased to `85` observations, the
association is highly significant, and the direction agrees with the domain-age
risk hypothesis. The finite, non-zero-cell OR avoids the earlier infinite-OR
failure mode; the only reason the point estimate reaches the maximum is the
chosen 0–30 log-odds mapping.

This remains an observational case-control calibration, not a causal estimate.
ThreatFox membership is an independently sourced malicious label, while Tranco
top-list membership is an independently sourced clean proxy rather than a
guarantee that a domain is harmless. WHOIS failures were excluded rather than
treated as clean or malicious, and the missingness mechanism may affect the
estimate. This historical `+30` proposal was not adopted. Commit `bb16056`
removed the numeric domain-age/DGA bonuses; the calculation and artifacts are
retained for reproducibility.

**Reproducibility artifacts:**
`scripts/adhoc/domain_age_calibration.py`,
`scripts/adhoc/case_control_malicious.json`,
`scripts/adhoc/case_control_clean.json`,
`scripts/adhoc/case_control_whois_results.jsonl`, and
`scripts/adhoc/case_control_calibration_summary.json` (gitignored adhoc files).

## Phase 4 Gmail OAuth implementation update — 17 Sep 2026

**Status:** `[x]` credential lifecycle implemented and verified; Phase 5 email
delivery through `NotificationManager` remains out of scope.

Implementation commit: `97f7aa5`.

- Added migration 007 for per-user Gmail tokens, SQLite OAuth state, and
  connect/disconnect/refresh-failure audit events; migrations 001–006 were not
  changed.
- Added fail-closed MultiFernet refresh-token encryption using only
  `GMAIL_TOKEN_ENCRYPTION_KEY`, with multi-key decryption support.
- Added owner-only connect/callback/status/disconnect routes and admin-only
  aggregate summary. No endpoint accepts `user_id` from query/body, and no
  token or ciphertext is returned to API/UI consumers.
- Requests only `gmail.send`, `openid`, `email`, and `profile`; OAuth tests mock
  Google and do not perform a real browser login.
- Added the Gmail settings card and negative/security coverage for state
  expiry/replay/mismatch, unauthenticated access, ciphertext secrecy,
  idempotent disconnect, remote-revoke failure, and migration constraints.
- Verification: targeted Phase 4 tests `8 passed`; related auth/visibility tests
  `154 passed`; full suite `1595 passed, 12 warnings, 8 subtests passed`.

## Phase 5 notification routing implementation — 17 Sep 2026

**Status:** `[x]` role-based Gmail routing, deduplication, SUSPICIOUS digest,
and Direct Flow A triggers implemented.

- Migration 008 adds transactional `notification_dedup` and
  `notification_digest_queue` tables without changing migrations 001–007.
- `verdict_alert` routes to SOC Analyst Tier 1-2 and Team Lead;
  `approval_required` routes only to Incident Responder; `action_executed`
  routes directly to `approved_by`.
- Gmail delivery uses each active user's linked OAuth credential. Missing,
  revoked, or refresh-failed accounts are skipped with structured safe logs;
  SMTP and LINE remain parallel channels.
- MALICIOUS is realtime, SUSPICIOUS is queued for a 15-minute asyncio digest,
  CLEAN/UNKNOWN are suppressed. Deduplication uses a five-minute window and
  event/verdict/normalized-IOC/recipient key.
- IOCInvestigator and MalwareAnalyzer now emit `verdict_alert` from Direct
  Flow A after verdict calculation; ticket creation remains independent.
- Verification: Phase 5 tests `10 passed`; related OAuth/playbook tests
  `33 passed`. Full suite in the current dirty worktree: `1603 passed`, `2
  pre-existing failures` in `scripts/eval/eval_benchmark.py` compatibility
  tests, `8 subtests passed`.

## Consensus Boost Multiplier — Empirical Grounding

The boost direction is empirically supported: at threshold `sources_flagged>=2`,
the raw OR Wilson CI lower bound is `1.372902`, which is greater than `1`.
The exact multiplier magnitude cannot be derived from this benchmark because
of perfect separation.

The consensus boost OR analysis used `894` records from the Group A benchmark.
The bucket table shows perfect separation: `sources_flagged>=1` is `100%`
MALICIOUS (`332/332`, `21/21`, `2/2`), while `sources_flagged=0` is `65.7%`
MALICIOUS (`354/539`). Raw `OR(>=2 vs <2) = inf`, Wilson CI lower bound =
`1.372902`. Raw `OR(>=3 vs <3) = inf`, Wilson CI lower bound = `0.115896`.
Perfect separation means point-estimate OR cannot be computed by standard
methods.

Haldane-Anscombe continuity correction was applied by adding `0.5` to every
cell of the `2x2` table before computing OR, the standard method for zero-cell
tables (Haldane 1956 / Anscombe 1956):

- Threshold `>=2`: `a=23.5, b=0.5, c=686.5, d=185.5 -> OR ~= 12.7`
- Threshold `>=3`: `a=2.5, b=0.5, c=707.5, d=185.5 -> OR ~= 1.31`

`OR~=1.31` at threshold `>=3` is close to the existing `1.3` multiplier; this
is an observation, not proof of correctness. These corrected OR values are an
interim justification, not proof of the exact multiplier.

An empirical false-positive search was performed as a negative result. MISP
misp-warninglists (`github.com/MISP/misp-warninglists`) were searched for IPs
in the Group A benchmark (`154` IP-type records, `130` with
`sources_flagged>=1`) matching known-scanner CIDR ranges.

- Scanner lists: `shodan-scanning` (`104` networks), `censys-scanning`
  (`23`), `rapid7-nt-scanning` (`18`), and `shadowserver` (`40`) produced
  `0` matches.
- Cloud-provider lists: `amazon-aws` (`3868` networks), `microsoft-azure`
  (`2335`), `digitalocean` (`234`), and `cloudflare` (`22`) produced `11`
  matches. Manual review showed all `11` have
  `expected_verdict=MALICIOUS` (confirmed C2/malware hosted on cloud VPS
  infrastructure, not false positives).
- Cloud IP ranges are used by both legitimate traffic and malicious actors;
  cheap, low-verification VPS hosting is common C2 infrastructure, so range
  membership alone carries no clean/malicious signal here.

No usable false-positive candidates were found within the time available. This
is a negative result from a genuine attempt, not a skipped step.

### Future Work

- Collect false-positive IOCs specifically for `spamhaus`/`c2_trackers` (the
  only two sources with nonzero signal in Group A).
- Collect a minimum `~10-15` confirmed clean examples in the
  `sources_flagged>=1` zone to break perfect separation.
- Investigate source delisting/retraction logs and manually curated gray-zone
  IPs. Cloud VPS and public scanner ranges were tried and ruled out this
  session.

## Phase 6 MCP management authentication implementation - 17 Sep 2026

**Status:** `[x]` MCP management RBAC, static tool classification, audit
logging, and playbook dispatch enforcement implemented.

- Migration 009 adds `mcp_management_audit` with actor, action, server,
  status, and timestamp fields only; no token, secret, or raw configuration.
  Migrations 001-008 remain unchanged.
- MCP management reads require authentication; mutations and SSRF-prone
  checks are admin-only. Server responses are role-sanitized and never return
  tokens/secrets, including to admin. There is no direct MCP execute endpoint.
- The eight configured MCP servers use an explicit static tool allowlist.
  Unknown tools are dangerous/unclassified by default, so Threat Hunter
  discovery and execution fail closed. Discovery metadata is replaced with
  trusted local classification before registry or dispatcher use.
- AgentLoop and PlaybookEngine now carry role/context into the final dispatch
  guard, including the previously unregistered MCP fallback path. The MCP
  HTML management page is admin-only.
- Verification: Phase 6 security tests `32 passed`; related MCP/playbook
  regression tests `43 passed`; staged implementation commit `08411de`.

## Access-request two-tier invitation amendment - 18 Sep 2026

**Status:** `[x]` public Team Lead request queue and scoped Team Lead member
invitation capability implemented.

This is an intentional amendment to the earlier D10.8 restriction that said
Team Lead could not invite users. The original restriction remains true for
admin and Team Lead account creation: public requests are now Team Lead-only,
admin continues to approve those requests and retains the unrestricted
admin-only invite endpoint, while an authenticated Team Lead may invite only
`SOC Analyst Tier 1-2`, `Incident Responder`, or `Threat Hunter` through the
separate Team Lead invite endpoint. Team Leads cannot invite another Team Lead
or an admin. The existing token creation, duplicate checks, expiry, and email
delivery path are shared rather than duplicated.

`/management` is now available to both `admin` and `Team Lead`, with the admin
access-request approval queue shown only to admins and the scoped member
invitation form shown only to Team Leads. CSRF and role checks remain enforced
server-side.

## Ticket ownership filtering — 20 Sep 2026

**Status:** implementation committed; post-commit full-suite verification follows.

- Ticket storage remains in the separate SQLite database selected by
  `TICKETING_DB_PATH`. Migration `011_add_ticket_owner.py` adds nullable
  `owner_id` and an index; existing tickets remain ownerless and are not
  backfilled.
- SOC Analyst Tier 1-2, Incident Responder, and Threat Hunter ticket queries
  filter by their own `owner_id`. Team Lead and admin use the unscoped query,
  which includes ownerless legacy tickets.
- Ticket creation receives the initiating user ID through IOC analysis,
  file/email analysis background jobs, and playbook sessions. Agent IOC tool
  dispatch also forwards its session owner.
- Verification: ticket ownership focused tests `61 passed`; full suite
  `1746 passed`, `5 failed`, `8 subtests passed`. The five failures are in
  pre-existing eval, scoring, and theme work outside this ticket-ownership
  change.

## Scoring aggregation formula and boost calibration decision — 20 Sep 2026

**Decision:** Dividing by `weight_sum` in the AHP scoring formula is intentional.
The production base score is `sum(weighted_scores) / weight_sum`, with the
active AHP multipliers accumulated into `weight_sum`
(`src/scoring/intelligent_scoring.py:193-197`). The current multi-source boosts
are `1.20` for exactly 2 flagged sources and `1.30` for 3 or more.

**Supersession:** The prior statements at lines 84-88 and 342-345 are stale for
the current aggregation decision. In particular, line 84 records `1.20` for 3+
and `1.15` for 2+, while line 342 records `1.30` for 3+ and `1.15` for 2+.
Use this entry for the current values and evidence; the earlier entries remain
unchanged as audit history.

### 2-source boost calibration under `weight_sum`

The current 2-source boost is `1.20`, changed from `1.15`. A paired bootstrap
comparison of `1.15` vs `1.20`, using scores computed with `weight_sum`, gave
`Diff=+0.0000`, `95% CI [+0.0000, +0.0000]`, with `n=21` 2-source records.
None of those 21 records had a `base_score` in `[41.67, 43.48]`, the only range
where changing the boost from `1.15` to `1.20` can flip classification at
`threshold=50`.

There is no empirical evidence supporting or rejecting `1.20` vs `1.15` under
the current formula. This is not because a boost cannot affect outcomes in
principle; the sample is small and has no records at the decision boundary. The
previous calibration result, `95% CI [+0.0164, +0.0414]` with `n=22`, is no
longer applicable because it measured scores under the pre-`weight_sum` formula.

### Formula comparison on the Group A benchmark

The old divisor (number of sources) and `weight_sum` were compared on the same
`894`-record Group A benchmark, holding boosts equal at `1.20` for 2 sources
and `1.30` for 3+ sources. The corresponding score files are
`scripts/eval/eval_results_group_a_v3_rich_oldformula.jsonl` and
`scripts/eval/eval_results_group_a_v3_rich_weightsum.jsonl`.

- Overall: `F1(old)=0.2443`, `F1(weight_sum)=0.5892`, `Diff=+0.3449`,
  `95% CI [+0.3176, +0.3709]`.
- 0-source (`N=539`): `Diff=+0.0000`; no source flags and the scores are equal
  under both formulas.
- 1-source (`N=332`): `F1(old)=0.0752`, `F1(weight_sum)=1.0000`,
  `Diff=+0.9248`.
- 2-source (`N=21`): `F1(old)=0.4878`, `F1(weight_sum)=1.0000`,
  `Diff=+0.5122`, `95% CI [+0.0000, +0.5385]`.
- 3+-source (`N=2`): `Diff=+0.0000`; the sample is too small for a meaningful
  conclusion.

### Ground-truth coverage limitation

| `sources_count_group` | MALICIOUS/DGA | Other (clean) | Total |
|---|---:|---:|---:|
| 0-source | 354 | 185 | 539 |
| 1-source | 332 | 0 | 332 |
| 2-source | 21 | 0 | 21 |
| 3+-source | 2 | 0 | 2 |

All `185` (`100%`) clean records in this benchmark are in the 0-source group.
There are no clean records with one or more source flags. Therefore, F1
differences in the 1-source, 2-source, and 3+-source groups provide
recall-side evidence on malicious records only; they cannot measure the effect
of `weight_sum` on the false-positive rate for clean IOCs flagged by one or
more sources. This is a gap in the current benchmark, not evidence about the
formula. More clean IOCs with 1, 2, or 3+ source flags are needed to evaluate
false-positive impact.

All experiments in the 2-source calibration, formula comparison, and coverage
analysis above use the same `894`-record Group A benchmark that was used for
the earlier boost calibration. Results therefore carry a risk of overfitting
to this one dataset.

## Scoring formula, boost selection, and Spamhaus notes — 2026-09-21

### 1. สูตรรวมคะแนน (divisor)

- [x] สูตรเดิมหารผลรวมคะแนนถ่วงน้ำหนักด้วยจำนวน source ที่มีคะแนนบวก; ThreatFox `90 x 0.33961 = 30.5649` ได้ `threat_score=30` หลังปัดจำนวนเต็ม จึงเป็น CLEAN ที่ threshold `50` ในตัวอย่าง `pbl_examples.txt`. สูตรปัจจุบันหารด้วย `weight_sum` เพื่อ normalize ด้วยน้ำหนัก AHP ที่ใช้จริง. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/pbl_examples.txt`; `src/scoring/intelligent_scoring.py:191-200`.
- [x] Stage 0 gate คำนวณซ้ำจาก `sources.*.score` เทียบ `threat_score` ได้ `894/894` สำหรับสามชุดพารามิเตอร์นี้:

  | ไฟล์ข้อมูล | divisor | boost 2 source | boost 3+ source | ผล gate |
  |---|---|---:|---:|---|
  | `v3_rich` | `count` | `1.15` | `1.30` | `894/894 PASS` |
  | `weightsum` | `weight_sum` | `1.20` | `1.30` | `894/894 PASS` |
  | `oldformula` | `count` | `1.20` | `1.30` | `894/894 PASS` |

  ชื่อไฟล์ข้อมูลใน gate คือ `scripts/eval/eval_results_group_a_v3_rich.jsonl`, `scripts/eval/eval_results_group_a_v3_rich_weightsum.jsonl`, `scripts/eval/eval_results_group_a_v3_rich_oldformula.jsonl`. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/gate_results.txt`.
- [x] ผล S1 (`count`, `1.15/1.30`) มี Macro F1 `0.2155`, 95% CI `[0.1903, 0.2398]`; ผล S3 (`weight_sum`, `1.20/1.30`) มี Macro F1 `0.5892`, 95% CI `[0.5562, 0.6200]`. CI ทั้งสองไม่ทับกัน แต่ยังไม่ได้ทำ paired bootstrap ของผลต่าง S1 กับ S3 โดยตรง; ค่าบูสต์ของสองชุดต่างกันด้วย. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/S1_results.txt`, `S3_results.txt`.

### 2. Boost multiplier: วิธีเลือกค่า

- [x] เกณฑ์ค่าเฉลี่ยจาก `S3_as_is` ใน `score_group_summary.csv`: กลุ่ม 1 source เฉลี่ย `89.186747` หรือ `89.19`; กลุ่ม 2 source ที่ boost `5%` เฉลี่ย `87.476190` หรือ `87.48` ซึ่งต่ำกว่า; ที่ `10%` เฉลี่ย `91.428571` หรือ `91.43` ซึ่งสูงกว่า. จุดตัดของเกณฑ์นี้อยู่ราว `7%`.
- [x] เกณฑ์ไม่ชนเพดาน `100`: กลุ่ม 2 source ที่ `20%` เฉลี่ย `99.047619` หรือ `99.05`; ที่ `25%` ขึ้นไป คะแนนเฉลี่ยและคะแนนต่ำสุดเป็น `100` เท่ากันทั้ง `21` รายการ.
- [x] เกณฑ์ threshold sweep: ที่ threshold `95` ใน S3 ค่า F1 เพิ่มจาก `0.176147` ที่ boost `10%` เป็น `0.206610` ที่ `15%`; ค่า `15%` และ `20%` เท่ากัน. หลักฐานของเกณฑ์ทั้งสามข้อ: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/score_group_summary.csv`, `threshold_sweep.csv`.
- [x] ช่วงที่ผ่านเกณฑ์ข้างต้นคือ `15-20%`; ข้อมูล threshold sweep แยก `15%` กับ `20%` ไม่ออก จึงคง `1.20` (เพิ่ม `20%`) ที่ scorer ใช้อยู่ เป็นกฎ tie-break และไม่ใช่ผลทดลองว่าค่านี้เหนือกว่า `15%`. หลักฐานค่าปัจจุบัน: `src/scoring/intelligent_scoring.py:210-214`; ผล sweep: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/threshold_sweep.csv`.
- [x] Boost `3+` คง `1.30` ตามการออกแบบ; S3 มี `n=2`, S4 หลัง exclude PBL มี `n=1`, และคะแนนเต็ม `100` ทั้งกลุ่ม จึง calibrate ค่ากลุ่มนี้จากข้อมูลชุดนี้ไม่ได้. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/S3_results.txt`, `S4_results.txt`, `score_group_summary.csv`.
- [x] ที่ threshold `50` ค่า Macro F1 ของ S3 คง `0.589171` ทุก boost ที่ sweep; คะแนนเฉลี่ยกลุ่ม 2 source เป็น `83.428571` ก่อน boost, `95.238095` ที่ `15%`, `99.047619` ที่ `20%`. AUC/AP diff เป็น `0` ใน threshold-free metrics; source-flagged records ใน Group A เป็น MALICIOUS ทั้งหมด จึงไม่ใช้ diff `0` เป็นเหตุผลเลือก boost. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/threshold_sweep.csv`, `score_group_summary.csv`, `threshold_free_metrics.csv`, `S3_results.txt`.
- [x] ตัวเลขจากสูตร count ที่ไม่ใช่ผลของสูตรปัจจุบัน: Macro F1 `0.2443`, diff `+0.0288`, 95% CI ของ diff `[+0.0164, +0.0414]`, ชนะทุกรอบ bootstrap `100%`; ทำซ้ำได้ใน S1 โดยเปรียบเทียบ count+`1.15/1.30` กับ count+`1.20/1.30` เท่านั้น. ผลนี้มาจาก `20` IOC ที่คะแนนเปลี่ยนจาก `49` เป็น `51`; `49` ต่ำกว่าเส้นตัด `50` หนึ่งคะแนน. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/S1_results.txt`, `pbl_examples.txt`.
- [x] PR-curve ของ S3 ที่ threshold `0` รายงาน positive-class F1 `0.8846`, precision `0.793` (`709/894`), recall `1.0`; threshold `0` ทำนายทุกรายการเป็น MALICIOUS จึงไม่ใช่ผลการทำงานของระบบที่ threshold ใช้งาน. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/sweep_results.txt`, `S3_pr_curves.csv`.

### 3. Spamhaus return codes

- [x] `check_spamhaus()` ที่ `src/integrations/threat_intel_extended.py:262-291` ตั้ง `found=True` เมื่อ DNS resolve สำเร็จ และไม่แยก return code. ใน tests ที่ค้นพบ `tests/test_threat_intel_source_accounting.py:121,193` มีเพียง mock การเรียก method; ไม่มี test ตรวจการแปล return code.
- [x] Group A มี Spamhaus hits `49` รายการ: `33` PBL-only (`127.0.0.10/11`) และ `16` รายการมี code อื่น. DNS ที่เก็บวันที่ `2026-09-21` ตรงกับ cache `49/49`. ไม่พบ `127.255.255.x` ในชุด code ที่ตรวจ. หลักฐาน: `evidence/source_weights_2026-09-21/spamhaus_codes_group_a_2026-09-21.jsonl`, `spamhaus_pbl_sensitivity_2026-09-21.json`.
- [x] Holdout overlap มี clean proxy ที่ Spamhaus ติดธง `21` รายการ: `20` ตอบ `127.0.0.11` และ `1` ตอบ `127.0.0.2` (`39.109.117.195`). Manifest ระบุรายการหลังเป็น clean proxy จาก public DNS ที่ยังไม่ยืนยัน จึงไม่นับเป็น false positive ที่ยืนยันแล้ว. หลักฐาน: `evidence/source_weights_2026-09-21/independent_external_proxy_holdout_2026-09-21.json`, `independent_external_proxy_holdout_overlap_2026-09-21.json`.
- [x] เมื่อ exclude PBL, F1 ของ S3→S4 เปลี่ยนจาก `0.589171` เป็น `0.571506`. สำหรับการนับจาก `sources_flagged` ใน S1→S2 ค่า `n(2-src)` เปลี่ยน `22→9`; การนับจาก scorer-status เปลี่ยน `21→8`. ใน S3→S4 ทั้ง record `sources_flagged` และ scorer-status เปลี่ยน `21→8`. จำนวนเหล่านี้นับคนละแบบใน S1/S2; Group A มี clean IP เพียง `3` รายการ จึงวัดผลของ PBL ต่อ false positive ไม่ได้. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/S1_results.txt`, `S2_results.txt`, `S3_results.txt`, `S4_results.txt`, `spamhaus_pbl_sensitivity_2026-09-21.json`, `scripts/eval/eval_results_group_a_v3_rich.jsonl`.
- [ ] ยังไม่ได้แก้ scorer ให้แยก Spamhaus PBL; เป็น future work หลังงานนี้. หลักฐานพฤติกรรมปัจจุบัน: `src/integrations/threat_intel_extended.py:262-291`; รายละเอียดผลทดสอบในหัวข้อนี้.

### 4. สถานะและข้อจำกัด

- [x] ไม่มีผลประเมินสูตร/boost บน held-out set: การเลือกค่าและตัวชี้วัดข้างต้นใช้ Group A ชุดเดียวกัน. มี manifest holdout `780` records และไฟล์ overlap แต่ไม่ได้คำนวณผล scoring บนชุดนั้น. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/S1_results.txt`, `S3_results.txt`, `evidence/source_weights_2026-09-21/independent_external_proxy_holdout_2026-09-21.json`, `independent_external_proxy_holdout_overlap_2026-09-21.json`.
- [x] `ThreatFox` ไม่อยู่ใน `TARGET_SOURCES` ของ `scripts/eval/collect_holdout_source_overlap.py:28`; holdout overlap จึงไม่วัด source นี้.
- [x] guard ปัจจุบันใน `scripts/eval/collect_holdout_source_overlap.py:82-89` กำหนดให้ `records` เป็น list ที่ไม่ว่าง; script ยัง untracked และยังไม่ commit. หลักฐาน: `scripts/eval/collect_holdout_source_overlap.py`.
- [x] Worktree มีไฟล์ค้าง: `src/scoring/intelligent_scoring.py` เป็น tracked file ที่แก้ไขแล้วยังไม่ commit; `scripts/eval/eval_results_group_a_v3_rich*.jsonl`, `paired_bootstrap_f1_ci.py`, `grid_search_boost_v2.py` เป็น untracked; `evidence/` ถูก ignore. สถานะ: `git status --short`; ignore rule: `.gitignore`.
- [x] `paired_bootstrap_f1_ci.py` ย้อนคะแนน 2-source ด้วย `1.20`, ส่วน `grid_search_boost_v2.py` ใช้ `1.15`; ทั้งคู่เป็นการคำนวณแบบย้อนจากไฟล์ v3_rich/count และสมมติฐานต่างกัน. Gate ยืนยันว่า v3_rich ตรงกับ count+`1.15/1.30` (`894/894`), ไม่ใช่การย้อนด้วย `1.20`; ใช้ `recompute_boost.py` คำนวณจาก `sources.*.score` แทน. หลักฐาน: `scripts/eval/paired_bootstrap_f1_ci.py`, `scripts/eval/grid_search_boost_v2.py`, `evidence/source_weights_2026-09-21/final_boost_2026-09-21/gate_results.txt`, `evidence/source_weights_2026-09-21/final_boost_2026-09-21/recompute_boost.py`.
- [ ] คำสั่งทำซ้ำที่บันทึกไว้ (ไม่ได้รันซ้ำในงานนี้): `D:\ai_cti_automate\evidence\source_weights_2026-09-21\final_boost_2026-09-21\run_all.ps1 -Set S1`; `D:\ai_cti_automate\evidence\source_weights_2026-09-21\final_boost_2026-09-21\run_all.ps1 -Set S3`; `D:\ai_cti_automate\evidence\source_weights_2026-09-21\final_boost_2026-09-21\run_sweep.ps1`. หลักฐาน: `evidence/source_weights_2026-09-21/final_boost_2026-09-21/run_all.ps1`, `run_sweep.ps1`.
## ข้อจำกัดคะแนน Email/Malware

หัวข้อนี้บันทึกข้อจำกัดของหน้าวิเคราะห์ Email และ Malware ซึ่งเป็นหน้าสำหรับนักวิเคราะห์ดูเท่านั้น และไม่ควรถูกรวมเข้า IOC scoring (Flow A)

### Email

- คะแนน Email ปัจจุบันนับสัดส่วนปัจจัยที่ตรวจได้และพบ โดยทุกปัจจัยมีน้ำหนักเท่ากัน; ปัจจัยที่มีสถานะ `unavailable` ไม่ถูกนับในตัวตั้งหรือตัวหาร (`src/scoring/intelligent_scoring.py:440-458`).
- กลุ่มปัจจัยปลอมตัวที่ทำให้ verdict เป็น `PHISHING` มีเพียง `brand_impersonation`, `lookalike_domain` และ `mixed_script` (`src/tools/email_analyzer.py:815-823`). `link_mismatch` ยังนับเป็นปัจจัยและทำให้เป็น `SUSPICIOUS` ได้ แต่ไม่อยู่ในกลุ่มปลอมตัวนี้ (`src/tools/email_analyzer.py:730-731`, `:824-826`).
- Verdict ของ Email มี 4 ค่า: `UNKNOWN` เมื่อ `checkable == 0`, `PHISHING` เมื่อพบปัจจัยปลอมตัว, `SUSPICIOUS` เมื่อพบปัจจัยอื่น และ `CLEAN` เมื่อไม่พบปัจจัย (`src/tools/email_analyzer.py:813-826`).
- ผล IOC และผลวิเคราะห์ไฟล์แนบยังถูกแสดงเป็นหลักฐานเสริม แต่ไม่เข้าคะแนน Email; โค้ดกำหนด `composite_score = base_score` และระบุข้อจำกัดนี้ไว้โดยตรง (`src/tools/email_analyzer.py:381-386`).
- ใน production wiring สำเนา IOC investigator และ MalwareAnalyzer สำหรับ Email จะถูกสร้างเมื่อ instance ต้นฉบับมีอยู่ และตั้ง `notification_manager = None`; สำเนาใช้ resource ที่คัดลอกแบบ shallow copy (`src/web/app.py:318-334`).
- `create_on_verdict_email` เป็น key แยกจาก IOC/Malware และค่าจริงใน `config.yaml` คือรายการว่าง `[]` (`config.yaml:137-143`). โค้ด Email มีค่า fallback `['PHISHING', 'SUSPICIOUS']` เฉพาะกรณีไม่มี key (`src/tools/email_analyzer.py:540-543`).

### Malware / File

- File scoring ใช้ `FILE_TOOL_WEIGHTS` ดังนี้: `capa=0.25`, `floss=0.15`, `diec=0.12`, `pe_analysis=0.15`, `static_analysis=0.10`, `binwalk=0.08`, `yara=0.15`, `threat_intel=0.20`, `strings=0.10`, `shellcode=0.15`, `packer=0.12` (`src/scoring/tool_based_scoring.py:42-55`).
- Verdict ทั่วไปของ File ใช้ `MALICIOUS` ที่คะแนนตั้งแต่ 70, `SUSPICIOUS` ที่คะแนนตั้งแต่ 40 และต่ำกว่านั้นเป็น `CLEAN` (`src/scoring/tool_based_scoring.py:86-90`, `:125-133`). นอกจากนี้ ransomware มีการบังคับคะแนนขั้นต่ำแยกที่ 70 และ 40 (`src/scoring/tool_based_scoring.py:600-607`).
- MalwareAnalyzer เรียก `ToolBasedScoring.calculate_file_score` เพื่อสร้าง `composite_score` และ verdict (`src/tools/malware_analyzer.py:463-468`).

### Ticketing และการแจ้งเตือน

- Malware และ IOC ใช้ key ร่วมกันคือ `ticketing.create_on_verdict`; Malware อ่านที่ `src/tools/malware_analyzer.py:643-646` และ IOC อ่านที่ `src/tools/ioc_investigator.py:427-431`. ค่าใน config ปัจจุบันคือ `MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN` (`config.yaml:137-142`).
- ข้อความว่า Email copy ไม่มี `notification_manager` เป็นจริงเฉพาะเมื่อ production wiring มี `email_analyzer` และต้นฉบับ IOC investigator/MalwareAnalyzer ตามเงื่อนไขใน `src/web/app.py:325-334`; ไม่ใช่ guarantee เมื่อ instance ต้นฉบับสร้างไม่สำเร็จ.


## 2026-10-09: source errors and coverage accounting

- Scoring now treats explicit source errors/unavailability as unavailable rather than clean. `_is_source_error()` is shared by scoring and source coverage; `_get_source_score()` returns `None` for errors. Coverage exposes `sources_ok` and `sources_applicable`.
- The initial scoring-only replay changed 25 rows to `UNKNOWN` (24 expected `CLEAN`, one expected `MALICIOUS`). These were an eval-export artifact, not a production coverage failure: production's trusted-infrastructure path returns `CLEAN` before scoring, while the exporter had converted its empty source map into six unavailable placeholders. The replay now honors `trusted_shortcut=true` with `sources_checked=0` using the recorded production verdict. Of the 435 expected-clean rows, 411 were source-scored and 24 used the trusted shortcut. Of 709 expected-malicious rows, 708 were source-scored and one (the Microsoft security blog URL) used the trusted shortcut. The four unsupported domain/URL sources remain an applicability follow-up; they were not provider failures.
- With trusted-shortcut rows treated as production records, all 1,144 rows have verdict counts 355 `MALICIOUS`, 789 `CLEAN`, 0 `UNKNOWN`, and 0 `SUSPICIOUS`; headline metrics are accuracy 69.1%, precision 100.0%, recall 50.1%, F1 66.7%. The 1,119 source-scored subset has metrics accuracy 68.5%, precision 100.0%, recall 50.1%, F1 66.8%.
- Reproduce with `scripts/eval/replay_source_error_handling.py`; this comparison is in `scripts/eval/output/source_error_handling_trusted_shortcut_replay.json`.


## 2026-10-09: scorer-consistent source display

- Scored-source Flagged/Clean state and Top source come from `score_breakdown` as the single source of truth. AlienVault and VirusTotal are context sources and do not contribute to IOC scoring.
