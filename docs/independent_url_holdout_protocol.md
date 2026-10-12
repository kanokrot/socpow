# Protocol: Independent URL Holdout (CABTA Flow A) — Draft v4

สถานะ: **DRAFT v4 — ห้ามดึงข้อมูลจนกว่าจะกรอกช่อง [TBD] ที่เหลือและ commit ไฟล์นี้ รวมถึง scripts และ .gitignore exception ตาม checklist ในหัวข้อ 3**
เขียนเมื่อ: 2026-10-12
ผู้รับผิดชอบ: Babe Ruth

## 1. เป้าหมาย

ตอบข้อสงสัยของ reviewer (NCCY2026 Paper #37, Review A/B/C) เรื่อง sample-selection bias ของตัวเลข 91% ซึ่ง malicious IOC ถูกคัดจาก ThreatFox ที่ระบบใช้ให้คะแนนด้วย โดยทดสอบ Flow A บน **URL** ที่คัดและตัดสิน label จากแหล่งที่ไม่อยู่ใน 6 scoring sources (FeodoTracker, C2 Trackers, Spamhaus, Tor exit nodes, SSLBL, ThreatFox)

ขอบเขต: ชุดนี้ครอบคลุม **เฉพาะ URL** ไม่ใช่ IP, domain หรือ hash

## 2. แหล่งข้อมูล

### Malicious (ดึงแยก 2 รอบ ห้ามผสมก่อน freeze)

| รอบ | แหล่ง | หมายเหตุ |
|---|---|---|
| 1 | OpenPhish community feed | ฟรี ใช้ได้เฉพาะไม่แสวงหากำไร (อ้างอิงในรายงาน), มีเฉพาะ URL ที่ active ณ เวลาดึง; endpoint ในโค้ดคือ `https://openphish.com/feed.txt`; ต้องบันทึก raw response เป็น snapshot พร้อมเวลา UTC และ SHA-256 เพราะ `openphish_lookup` อ่าน feed แบบ live และไม่บันทึก snapshot |
| 2 | PhishTank (database download) | ที่ pull time ให้ดาวน์โหลด database ใหม่และ freeze พร้อม UTC timestamp, URL และ SHA-256; ใช้เฉพาะ `verified=yes` และ `online=yes`. Snapshot เดิม `evidence_raw/phishtank/verified_online.json` (76,125 records; mtime 2026-09-16 00:52:49 +07:00) เป็น fallback เท่านั้น; เวลา fetch ของ fallback ยัง [TBD — ต้องมี download log/header หรือ metadata จาก source] |

จำนวนเป้าหมาย malicious หลัง eligibility filter และ dedup: **200 URLs** — OpenPhish 100 และ PhishTank 100 แยกเป็นคนละรอบ ห้าม backfill ข้ามแหล่ง หากแหล่งใดมี eligible URLs ไม่ถึง 100 ให้รายงาน shortfall และจำนวนจริงแทนการเติมจากอีกแหล่ง
บันทึกจำนวนทุก stage แยกต่อแหล่ง: จำนวน raw, eligible, ซ้ำภายในแหล่ง, ซ้ำข้ามแหล่ง/ชุด dedup, selected และ dropped พร้อมเหตุผล
วิธีสุ่ม (ต้องเป็นวิธีที่ไม่ดูผลของระบบก่อน): seeded sampling ด้วย `random.Random(20261011)` หลัง eligibility filter และ dedup; เก็บ seed และลำดับ/manifest ที่ใช้เลือก

### Clean

- ที่มา: [VERIFIED — `scripts/benchmark/build_clean_ioc_additions.py:23-24`; metadata ของ Tranco list ID `8P4GV` ที่ผู้ใช้ให้จาก https://tranco-list.eu/list/8P4GV] ใช้ Tranco list ID `8P4GV`, สร้างครั้งแรก 21 September 2026; รวม Crux, Farsight, Majestic, Radar และ Umbrella ในช่วง 23 August 2026–21 September 2026 (30 วัน), Dowdall rule, pay-level domains only, ใช้ full list. Clean-additions เดิมใช้รุ่นเดียวกัน
- Rank range: **1,000–50,000 (ข้อเสนอใหม่สำหรับ holdout นี้ ไม่ใช่การต่อเนื่องจากชุดเดิม)**; [VERIFIED — ranks parsed from the existing clean-additions file; `build_clean_ioc_additions.py:77-114`] ข้อมูล clean-additions เดิมมี rank 98–406 และไม่มี rank filter
- จำนวน clean **เป้าที่ประกาศไว้เดิม**: **200 URLs**; จำนวน candidates **เป้าที่ประกาศไว้เดิม**: ประมาณ **300 URLs** ก่อน VT screening เผื่อ no-report/AMBIGUOUS attrition. [VERIFIED — `evidence/independent_url_holdout_2026-10-11/build_tranco_manifest.json` (`counts_by_stage`)] รอบแรกสุ่ม 400 domains และได้ 170 candidates; [VERIFIED — `evidence/independent_url_holdout_2026-10-11/label_clean_urls_vt_manifest.json` (`counts_by_stage`)] VT ให้ CLEAN 30, AMBIGUOUS 1, MALICIOUS 0, NO_REPORT (`http_404`) 139 และ SOURCE_ERROR 0. รอบสอง candidates [กรอกหลังดึง], CLEAN [กรอกหลัง label]. เป้าหมาย clean รวมประมาณ 60 เป็นเพียงเป้า; clean arm สุดท้ายคือ CLEAN รอบแรก 30 + CLEAN รอบสองเท่าที่ได้จริง
- เกณฑ์กรองด้วย VirusTotal (ใช้เป็น label เท่านั้น ไม่เข้า scoring): `0` non-excluded malicious engines = CLEAN; `1–2` = AMBIGUOUS และ drop; `>=3` = MALICIOUS และ drop จาก clean side; ไม่มี VT report/ไม่มี `last_analysis_results` = drop
- [VERIFIED — คำนวณซ้ำจาก raw reports และ candidate manifests: `scripts/adhoc/vt_holdout_batch1_candidates_2026-09-24.json`, `vt_holdout_batch2_candidates_2026-09-24.json`, `vt_holdout_batch3_candidates_2026-09-24.json`, `vt_holdout_batch3_topup_candidates_2026-09-24.json` และ matching pull files; relabel rule ที่ `scripts/adhoc/vt_holdout_merge_relabel.py:19-24`] เมื่อนับ MALICIOUS engines ทั้งหมดเทียบกับการตัด MalwareURL, Hunt.io Intelligence และ Criminal IP ออก พบ labels เปลี่ยน 3 candidates จาก 229: MALICIOUS→AMBIGUOUS 2 และ AMBIGUOUS→CLEAN 1; ทั้ง 3 มี `known_source=threatfox`. ตาม rule ปัจจุบัน (ตัด 3 engines) candidates ที่ drop เป็น AMBIGUOUS/no-report รวม 29 (24/5); แยกเป็น `threatfox` 12/5 และ `clean_pool` 12/0. ไม่พบ count 9 จากการคำนวณนี้; 9/14 ที่บันทึกในหัวข้อ 10 คือ URL false negatives จาก builder bug ไม่ใช่จำนวนที่เปลี่ยน label จาก VT engine exclusion. [NOT FOUND — paper/manuscript §3.4 ไม่อยู่ใน repo จึงยืนยันข้อความ rationale ไม่ได้]
- วิธีได้ URL ลึก: เปิด homepage ของแต่ละ Tranco domain ที่สุ่มได้ด้วย fixed User-Agent; ดึง `<a href>` ที่อยู่ใน registrable domain เดียวกันและมี path หรือ query; ตัด fragments; เลือกหนึ่ง URL ต่อ domain ด้วย `random.Random(20261011)`. เก็บ manifest ของ candidate links ทั้งหมดและ homepage SHA-256; skip และ log domain ที่ล้มเหลวหรือไม่มี internal link; ห้ามแก้ URL ที่เลือก. รอบสองใช้โดเมนตำแหน่ง 401–800 จาก sample ลำดับเดียวกัน; ใช้ candidate รอบแรกที่ freeze แล้วและห้ามดึง homepage ของ 400 โดเมนแรกซ้ำ

## 3. ขั้นตอน (ห้ามสลับลำดับ)

### Step 0 — เตรียมและ commit ก่อน pull ใด ๆ

- [ ] เขียนและ commit `scripts/eval/build_independent_url_holdout.py` ใน tracked location: pull/freeze OpenPhish และ PhishTank, eligibility filter, seeded sampling ด้วย `random.Random(20261011)`, dedup keys, per-row fields `sampling_source` และ `label_source`; เก็บ IOC URL ตามต้นฉบับ ห้ามแก้หรือ normalize URL
- [ ] เขียนและ commit `scripts/eval/measure_url_overlap.py` ใน tracked location: freeze C2 feeds และเก็บ ThreatFox raw lookup ต่อ IOC ก่อน eval; ทำ overlap โดยไม่เรียก scoring pipeline
- [ ] เขียนและ commit `scripts/eval/label_clean_urls_vt.py` ใน tracked location: ใช้ VT 3-tier rule; log ทุก candidate ที่ drop พร้อม reason (เช่น no report, missing `last_analysis_results`, AMBIGUOUS หรือ MALICIOUS)
- [ ] เขียนและ commit `scripts/eval/compute_holdout_metrics.py` ใน tracked location: Precision/Recall/F1 พร้อม Wilson 95% CI; แยก OpenPhish/PhishTank, overlap strata, 3-class counts และจำนวน rows ที่ source unavailable
- [ ] เขียนและ commit `scripts/eval/combine_independent_url_holdout.py` ใน tracked location: รวม `malicious_openphish.json`, `malicious_phishtank.json` และ `clean_labeled_final.json` ตามลำดับ; ปฏิเสธ label ที่ยังไม่ final และ IOC ซ้ำ
- [ ] เขียนและ commit `scripts/eval/combine_clean_url_rounds.py` ใน tracked location: รวม CLEAN รอบ 1 และ 2 โดยรักษา `counts_by_stage` แยกรอบและป้องกัน IOC ซ้ำ
- [ ] เตรียม dated evidence folder เช่น `evidence/independent_url_holdout_2026-10-11/` สำหรับ frozen source data, manifests และ checksums; `evidence/` ถูก ignore เว้นแต่ allowlist ไว้ใน `.gitignore`; เพิ่ม rule `!evidence/independent_url_holdout_2026-10-11/` หลัง `evidence/*` ก่อนเริ่ม pull (งานนี้ไม่แก้ `.gitignore`)
- [ ] วาง Tranco full-list CSV ใน `evidence/independent_url_holdout_2026-10-11/` และบันทึก SHA-256 ก่อนสร้าง clean candidates
- [ ] ก่อน pull ยืนยันว่า scripts และ `.gitignore` exception ถูก tracked/committed แล้ว

1. ดาวน์โหลด OpenPhish และ PhishTank แยกแหล่ง; ดาวน์โหลด Tranco full-list CSV ด้วยตนเองและบันทึก URL, UTC time และ SHA-256 ในหัวข้อ 7
2. Freeze raw response/files ก่อนกรอง แล้วบันทึก SHA-256 และ metadata ในหัวข้อ 7
3. ทำ eligibility filter และ dedup ภายใน/ข้ามรอบ; บันทึกจำนวนทุก stage และ shortfall โดยห้าม backfill ข้ามแหล่ง
4. ทำ VT clean screening ตาม 3-tier rule และ candidate order ที่ freeze ไว้: ใช้ CLEAN 30 จากรอบแรกและเพิ่ม candidate จากโดเมนตำแหน่ง 401–800 ตาม deviation ในหัวข้อ 8; เป้าหมาย clean **เป้าที่ประกาศไว้เดิม** คือ 200 แต่ clean arm ที่ใช้จริงคือ 30 + CLEAN รอบสองเท่าที่ได้ (รอบสอง [กรอกหลัง label])
5. รวมผล label clean รอบ 1 และรอบ 2 เป็น `clean_labeled_final.json` ด้วย `combine_clean_url_rounds.py`; ห้ามส่ง 170 URL เดิมเข้า VT ซ้ำและบันทึก counts แยกรอบ
6. รวม `malicious_openphish.json`, `malicious_phishtank.json` และ `clean_labeled_final.json` ตามลำดับด้วย `combine_independent_url_holdout.py`; ตรวจว่าไม่มี label ที่ยังไม่ final หรือ IOC ซ้ำ
7. วัด overlap **ก่อน eval และไม่ใช้ verdict/score ของระบบ** กับสอง source ที่ใช้กับ URL IOC ใน scoring path: C2 Trackers และ ThreatFox. สำหรับ C2 ให้ freeze raw copies ของ feed ทั้ง 10 ไฟล์ ณ pull time พร้อม UTC timestamp, source URL และ SHA-256 ต่อไฟล์; คำนวณ exact-URL match และ host-level match กับข้อมูลใน feed. สำหรับ ThreatFox แนะนำให้เก็บ raw API response ต่อ candidate โดยส่ง URL ต้นฉบับที่ไม่แก้ไข พร้อม UTC timestamp, request URL/query metadata และ SHA-256 ของ response; วิธีนี้รักษาความสัมพันธ์ระหว่าง IOC กับ query ต้นฉบับ และหลีกเลี่ยงการอาศัย export ที่จำกัด `THREATFOX_LIMIT=500` ต่อ fetch (`src/integrations/threat_feed_sync.py:28-38, 283-299`) หรือ export เก่า `evidence_raw/threatfox/threatfox_export_2026-09-16.json`. วัด exact-URL และ host-level match แยกกัน; บันทึก snapshot date, source URL/hash และแถวที่ไม่มี offline source data. URL IOC ไม่มี overlap check สำหรับ FeodoTracker, Spamhaus, Tor exit nodes และ SSLBL เพราะเป็น IP/hash-only sources (`src/integrations/threat_intel.py:1021-23, 1025-39, 1052-53`)
8. รัน eval เพียงครั้งเดียวด้วยระบบตามที่เป็นอยู่และไฟล์ `combined_holdout.json`
9. คำนวณและรายงานผลตามหัวข้อ 5

สถานะข้อมูลสำหรับ overlap (ผลตรวจ read-only):

- [VERIFIED — `src/integrations/threat_intel.py:520-555`; `src/integrations/threat_feed_sync.py:29-48`] FeodoTracker source URL คือ `https://feodotracker.abuse.ch/downloads/ipblocklist.json`; scorer โหลดสดและรองรับ IP เท่านั้น. มี sync DB ที่ `~/.blue-team-assistant/cache/threat_feed.db`; DB บนเครื่องที่ตรวจมี 5 Feodo IP rows, ขนาด 552,960 bytes, mtime/last success 2026-10-11. Sync ตั้ง limit 1,000, retention 30 วัน และ refresh ทุก 7 วัน. ตรวจ URL ได้เฉพาะ IP ของ URL host เทียบกับ source IP; ไม่มี exact-URL IOC
- [VERIFIED — `src/integrations/threat_intel.py:768-855`] C2 Trackers ดึง 10 feed URLs สดในแต่ละ lookup (รวม montysecurity, drb-ra, jmousqueton และ maltrail; endpoints อยู่ที่ lines 786-832) และค้น IOC ด้วย case-insensitive substring ใน feed text; request timeout คือ 10 วินาที และไม่พบ coded rate limit หรือ frozen C2 snapshot ใน repo/local sync DB. [NOT FOUND — frozen snapshot path/size/date; TBD: ต้อง freeze raw source files ก่อนใช้ offline] Exact URL/host/IP ตรวจได้จาก snapshot เมื่อ feed มีค่าที่ตรงกับแต่ละรูปแบบ; ต้องบันทึก feed ที่ตรวจครบและ search rule ใน manifest
- [VERIFIED — `src/integrations/threat_intel_extended.py:262-310`] Spamhaus ใช้ DNSBL `zen.spamhaus.org` สำหรับ IP เท่านั้นและ query DNS สด; ไม่ applicable กับ URL IOC ใน scoring path (IP-only).
- [VERIFIED — `src/integrations/threat_intel.py:688-717`] Tor exit nodes โหลด `https://check.torproject.org/torbulkexitlist` สดทุก lookupและตรวจ IP เท่านั้น; ไม่ applicable กับ URL IOC ใน scoring path (IP-only).
- [VERIFIED — `src/integrations/threat_feeds.py:64-76, 96-118, 213-269`] SSLBL ใช้ `https://sslbl.abuse.ch/blacklist/sslblacklist.csv` สำหรับ SHA1 certificate fingerprints และมี in-memory cache TTL เริ่มต้น 1 ชั่วโมง; ไม่มี URL-to-certificate association ใน path ที่ตรวจ จึงไม่ applicable กับ URL IOC ใน scoring path (SHA1-only).
- [VERIFIED — `src/integrations/threat_intel.py:557-645`; `src/integrations/threat_feed_sync.py:28-48`] ThreatFox live API endpoint คือ `https://threatfox-api.abuse.ch/api/v1/` และรองรับ URL/domain/IP IOC; scorer เรียก live API ไม่ได้อ่าน sync DB. แยกจาก scorer มี machine-local DB `~/.blue-team-assistant/cache/threat_feed.db` ที่ตรวจพบ 2,009 rows (286 URL), last success 2026-10-11 และไฟล์ export `evidence_raw/threatfox/threatfox_export_2026-09-16.json` ขนาด 13,985,212 bytes / 14,880 rows (672 URL; mtime 2026-09-16). Sync จำกัด 500 records ต่อ fetch, เก็บ 30 วันและ refresh ทุก 7 วัน. DB/export ใช้เป็น source data ได้เมื่อ freeze พร้อม hash/วันที่ แต่ไม่มี snapshot ที่ tracked สำหรับรอบใหม่นี้
- [VERIFIED — `scripts/eval/eval_benchmark.py:33-42`; `src/integrations/threat_intel.py:1017-1096`] URL scoring path มี C2 Trackers และ ThreatFox เท่านั้น; Feodo, Spamhaus, Tor และ SSLBL เป็น IP/SHA1-only sources ใน source implementation. การ overlap ที่วัดจาก source-data snapshots เป็นคนละหลักฐานกับผล scoring ของระบบ

## 4. การประเมิน

- ใช้ Flow A ครบ 6 scoring sources ตาม config ปัจจุบัน
- ก่อน full run ให้ทำ smoke test จาก 5 rows แรกของ **old holdout** (`evidence/vt_independent_holdout_2026-09-25/vt_holdout_eval_results_batch3_21.jsonl`); ทั้งห้าเป็น URL IOC และมี `expected_verdict`. สร้าง benchmark JSON array ด้วย fields `ioc`, `ioc_type`, `expected_verdict`, `source`, `collected_at`; รันภายใต้ isolated `USERPROFILE` และห้ามใช้ rows จาก new frozen set. ยืนยันว่า API key โหลดจาก isolated profile โดยบันทึกเพียงว่าพบ key (ห้าม log ค่า key); สำหรับ URL rows คาดว่า C2 Trackers เป็น `unavailable` ตามสถานะ 9/10 feeds ที่บันทึกไว้ ส่วน ThreatFox ให้บันทึก hit/miss และสถานะตามจริง. เก็บผล เวลา UTC จำนวนแถวที่ C2 Trackers เป็น `unavailable` และสถานะ ThreatFox ในหัวข้อ 7
- [VERIFIED — `scripts/eval/eval_benchmark.py:54-95, 204-208`] evaluator JSONL เก็บสถานะ/คะแนน/`unavailable`/`observed_at` แยกตาม source แต่ไม่เก็บ raw ThreatFox response; จึงบันทึก raw response จาก evaluator ไม่ได้ และการวิเคราะห์ FN ย้อนหลังถูกจำกัดด้วยข้อมูลที่ผลประเมินไม่มี (งานนี้ไม่แก้ evaluator)
- บันทึก environment ของ run: `LLM_DGA_VLLM_CANARY_PERCENT=100`, `BTA_CONFIG` unset. LLM-DGA ถูกเรียกใน environment นี้ แต่ไม่ส่งผลต่อ `threat_score` หรือ `predicted_verdict` สำหรับ URL IOC
- บันทึก git commit hash ของระบบ ณ ตอนรัน: [TBD]
- **ไม่แก้** น้ำหนัก AHP, multiplier, threshold หรือ config ใด ๆ ระหว่างขั้นตอนนี้
- Positive class = MALICIOUS; ใน binary metrics ให้นับ `SUSPICIOUS` และ `UNKNOWN` เป็น non-MALICIOUS/negative ตาม convention ของผล 91.0% เดิม และรายงานจำนวนทั้งสอง verdict แยกเป็น 3-class counts
- สำหรับ cold IOC cache ให้รัน evaluator ใน process ที่ตั้ง `USERPROFILE` เป็น directory เฉพาะของรอบนี้ (Windows; `Path.home()` ใช้ค่านี้) เพื่อให้ `IOCCache()` ใช้ `USERPROFILE/.blue-team-assistant/cache/ioc_cache.db`; เก็บ path, ขนาดไฟล์ และ mtime ก่อน run (ถ้ายังไม่มีให้บันทึกว่า absent) และหลัง run
- [VERIFIED — `src/cache/ioc_cache.py:37-39`; `src/integrations/threat_intel.py:65-77`; `scripts/eval/eval_benchmark.py:167-172`] ไม่มี cache DB env/config hook หรือ evaluator CLI arg; `IOCCache(db_path=...)` รองรับ constructor arg แต่ integration hardcodes `IOCCache()`. บน Windows ตั้ง `$env:USERPROFILE = '<run-specific directory outside the repo>'` ใน process ก่อนเรียก evaluator; `Path.home()` ใช้ค่านี้และทำให้ `IOCCache()` ใช้ profile directory แยกสำหรับรอบนี้
- [VERIFIED — `src/integrations/threat_intel.py:1129-1188`; `src/integrations/threat_feeds.py:64-76, 213-269`; `src/integrations/threat_feed_sync.py:470-519`] IOC cache lookup ใช้เป็น exception fallback; ThreatFeeds มี in-memory cache สำหรับ SSLBL SHA1 (default TTL 1 ชั่วโมง) ในการเรียกปกติ แต่ไม่ใช้กับ URL IOC; threat-feed DB ไม่ใช่ cache ที่ evaluator ใช้
- [INFERRED — estimate] เวลาประเมิน **ประมาณ 118 นาทีสำหรับ 400 rows ที่ `--delay 16`** (ประมาณการจาก timestamp proxy ของ URL ใน run เดิม ไม่ใช่เวลาที่วัดจริง); VT clean screening **ประมาณ 75–80 นาทีสำหรับ ~300 lookups** ที่ 4 requests/minute หรือ 16 วินาทีต่อ request
- ไม่ตั้งเกณฑ์ผ่าน/ไม่ผ่านล่วงหน้า (เช่น 80%) รายงานผลตามจริง
- คำสั่งสำหรับรอบใหม่ (ThreatFox overlap ใช้ default delay 2 วินาที; `--delay 16` ใช้กับ VT/eval เท่านั้น):

```powershell
$evidence = "evidence/independent_url_holdout_2026-10-11"
$oldHoldout = "evidence/vt_independent_holdout_2026-09-25/vt_holdout_eval_results_batch3_21.jsonl"
.venv\Scripts\python.exe -c "import json,pathlib; p=pathlib.Path('$oldHoldout'); rows=[json.loads(x) for x in p.read_text(encoding='utf-8').splitlines()[:5]]; records=[{'ioc':r['ioc'],'ioc_type':r['expected_ioc_type'],'expected_verdict':r['expected_verdict'],'source':r['source'],'collected_at':r['label_collected_at']} for r in rows]; out=pathlib.Path('$evidence/smoke_old_holdout.json'); out.write_text(json.dumps(records), encoding='utf-8')"
$env:USERPROFILE = "$evidence\smoke_userprofile"
.venv\Scripts\python.exe scripts/eval/eval_benchmark.py --benchmark "$evidence/smoke_old_holdout.json" --output "$evidence/smoke_eval_results.jsonl" --group-a-only --delay 0
.venv\Scripts\python.exe scripts/eval/build_independent_url_holdout.py --source openphish --out-dir $evidence --target 100 --seed 20261011
.venv\Scripts\python.exe scripts/eval/build_independent_url_holdout.py --source phishtank --out-dir $evidence --target 100 --seed 20261011 --dedup-against-round "$evidence/malicious_openphish.json"
.venv\Scripts\python.exe scripts/eval/build_independent_url_holdout.py --source tranco --out-dir "$evidence/clean_round2_build" --target 300 --seed 20261011 --input-file "$evidence/tranco_8P4GV.csv" --domain-offset 400 --domain-count 400 --dedup-against-round "$evidence/clean_candidates_tranco.json"
.venv\Scripts\python.exe scripts/eval/label_clean_urls_vt.py --input-file "$evidence/clean_round2_build/clean_candidates_tranco_round2.json" --out-dir "$evidence/clean_round2_vt" --target 200 --delay 16 --seed 20261011
.venv\Scripts\python.exe scripts/eval/combine_clean_url_rounds.py --round1 "$evidence/clean_labeled.json" --round1-manifest "$evidence/label_clean_urls_vt_manifest.json" --round2 "$evidence/clean_round2_vt/clean_labeled.json" --round2-manifest "$evidence/clean_round2_vt/label_clean_urls_vt_manifest.json" --out-dir "$evidence/clean_final"
.venv\Scripts\python.exe scripts/eval/combine_independent_url_holdout.py --openphish "$evidence/malicious_openphish.json" --phishtank "$evidence/malicious_phishtank.json" --clean "$evidence/clean_final/clean_labeled_final.json" --out-dir $evidence
.venv\Scripts\python.exe scripts/eval/measure_url_overlap.py --input-file "$evidence/combined_holdout.json" --out-dir "$evidence/overlap" --seed 20261011
.venv\Scripts\python.exe scripts/eval/eval_benchmark.py --benchmark "$evidence/combined_holdout.json" --output "$evidence/eval_results.jsonl" --group-a-only --delay 16
.venv\Scripts\python.exe scripts/eval/compute_holdout_metrics.py --eval-results "$evidence/eval_results.jsonl" --overlap-flags "$evidence/overlap/url_overlap_flags.json" --output "$evidence/holdout_metrics.json"
```

## 5. การรายงาน

- รายงานผล overlap หลักเป็นสัดส่วน malicious URLs ที่ทราบว่าอยู่ใน C2 Trackers หรือ ThreatFox ณ pull time พร้อม Wilson 95% CI; นี่คือ coverage ของแหล่งข้อมูลที่ระบบใช้ได้กับ URL
- รายงาน recall ของ malicious URLs ทั้งชุด และ recall ภายใน overlap stratum เป็น consistency check (คาดว่าใกล้ 100%; ตรวจสอบทุก miss)
- รายงานผลใน non-overlap stratum แยกต่างหาก พร้อมระบุชัดว่า URL ที่ไม่มีทั้ง C2 Trackers และ ThreatFox ตามนิยาม overlap ย่อม flag ไม่ได้จาก URL scoring path; ค่าต่ำใน stratum นี้จึงไม่ใช่ข้อค้นพบเกี่ยวกับคุณภาพ scoring
- นิยาม strata ตาม exact-URL match และ host-level match กับ frozen C2 feed files และ ThreatFox evidence ตาม step 4; รายงาน exact-URL/host-level แยกกัน รวมถึง rows ที่ source evidence ใช้ตรวจไม่ได้
- แสดง Precision, Recall, F1 พร้อมช่วงความเชื่อมั่น Wilson 95% (Precision และ Recall แยกกัน)
- แยกตัวเลขตามรอบ (OpenPhish / PhishTank) และรายการที่ปรากฏทั้งสองแหล่ง
- รายงานตามจริงไม่ว่าผลจะสูงหรือต่ำ

## 6. กติกาห้ามทำ

- ห้ามปรับระบบ (น้ำหนัก, threshold, multiplier, เพิ่ม/ลบ source) แล้วรันซ้ำบนชุดนี้
- ห้ามเพิ่มหรือตัดตัวอย่างหลังเห็นผล
- ถ้ามีการเปลี่ยนแปลงใด ๆ จากโปรโตคอลนี้ ต้องบันทึกในหัวข้อ 8 พร้อมเหตุผล และเขียนในรายงานด้วย

## 7. บันทึกการดึงข้อมูล (กรอกหลังดึง)

| รอบ | วันเวลา UTC | ไฟล์ | SHA-256 | จำนวน candidates/clean | จำนวนที่ตัด แยกเหตุผล |
|---|---|---|---|---:|---|
| OpenPhish | | | | | |
| PhishTank | | | | | |
| Clean รอบ 1 (candidates) | 2026-10-11T15:17:19.673954Z | `clean_candidates_tranco.json` | `9765be606926738705fc2cffe7fa1cbf28ae5560cf49211c462d3bc33827b94b` | 170 | 134 homepage fetch failed; 55 HTTP errors; 41 ไม่มี deep link; 0 dedup/overlap; shortfall 130 ต่อ target 300 |
| Clean รอบ 1 หลัง VT | 2026-10-11T15:58:04Z–16:45:00Z (ช่วง fetched reports) | `clean_labeled.json` | `1a0f4686d134ca8f8145f473efeaf39754a3c387a41402e101f6a8b52fde2773` | 30 CLEAN | 139 NO_REPORT/http_404; 1 AMBIGUOUS; 0 MALICIOUS; 0 SOURCE_ERROR; 0 CLEAN เกิน target |
| Clean รอบ 2 (candidates) | 2026-10-12T07:12:13.752659Z | `clean_round2_build/clean_candidates_tranco_round2.json`; manifest `clean_round2_build/build_tranco_round2_manifest.json` | `ba33e8da41ffd5c962087aa1cad9c09bbbb4fe8c1782f61c5efda3228c8fea08`; manifest `0f33bf871ddcf323f8fb1472db11d6b7fa6182400bfa27d6bee9cd06d881559b` | 188 จาก 400 domains (ตำแหน่ง 401–800; selected 188, shortfall ต่อ target 300 = 112) | 135 `homepage_fetch_failed`; 51 `homepage_http_error`; 26 `no_internal_deep_link`; 1 `candidate_shortfall`; exact/host overlap กับ 6 ไฟล์ที่ตรวจ = 0/0 ต่อไฟล์ |
| Clean รอบ 2 หลัง VT | 2026-10-12T07:54:55.614982Z–08:46:40.827463Z (fetched reports) | `clean_round2_vt/clean_labeled.json`; manifest `clean_round2_vt/label_clean_urls_vt_manifest.json` | `d7c831c5a31cf8b12d176f2da2a1c35501c4904832768baa414434b74f18bbdf`; manifest `6802296293e1db3d130ee90607af5457d8bfe652c631936d7dea96afcacc4dbf` | 26 CLEAN จาก 188 candidates | 160 NO_REPORT (`http_404`); 2 AMBIGUOUS; 0 MALICIOUS; 0 SOURCE_ERROR; 0 CLEAN เกิน target |
| Clean รวมสุดท้าย | 2026-10-12T09:07:05.017297Z (manifest `created_at_utc`) | `clean_final/clean_labeled_final.json`; manifest `clean_final/combine_clean_url_rounds_manifest.json` | `e41b309d3d873328e18f58787e6592df222a96623c3ef6ba52aeaed5eb45defd`; manifest `a7c95dc62648245eb293a99aad9b59ae3da522c29b399b2bca4366272f1c15a4` | 56 CLEAN (30 + 26) | 0 rows ถูกตัดตอนรวม; การตัดจาก VT อยู่ในแถวรอบ 1/2 ข้างต้น |
| C2 Trackers overlap snapshots (10 feed files; บันทึก URL, UTC time, SHA-256 แยกทุกไฟล์) | | | | | |
| ThreatFox per-candidate raw API results (query ด้วย original URL; UTC time และ SHA-256) | | | | | |
| Tranco full-list CSV (manual download; URL, UTC time, SHA-256) | | | | | |
| Smoke test (5 URL rows from old `vt_holdout_eval_results_batch3_21.jsonl`; isolated `USERPROFILE`; key loaded flag; ThreatFox/C2 status) | | | | | |

ผลการวัด overlap ของ URL กับ C2 Trackers และ ThreatFox: [กรอกหลังขั้นตอน 4; แยก exact-URL และ host-level counts, ระบุ snapshot date/source hash, และรายงาน rows ที่ตรวจจาก source evidence ไม่ได้เป็น NOT FOUND]
PhishTank snapshot เดิมใน repo มี 76,125 records; ทุก record ที่ตรวจมี `verified=yes` และ `online=yes` (0 offline/invalid rows ในไฟล์นี้). [VERIFIED — count parsed from `evidence_raw/phishtank/verified_online.json`]
การดึงรอบนี้ให้ใช้ database download ใหม่และบันทึก UTC time, URL และ SHA-256 ในแถว PhishTank ด้านบน; หากต้อง fallback ไปใช้ snapshot เดิม เวลา fetch ยัง [TBD — ต้องมี download log/header หรือ metadata ที่มากับ source; mtime 2026-09-16 00:52:49 +07:00 ยืนยันได้เพียงเวลาแก้ไขไฟล์]
[VERIFIED — `src/mcp_servers/free_osint_tools.py:83-113`] OpenPhish: `openphish_lookup` ดึง `https://openphish.com/feed.txt` สด ไม่มี local/feed cache และคืนผลตรวจพร้อม timestamp ตอน lookup; builder ต้องบันทึก raw feed response เป็นไฟล์ก่อน filter/sampling พร้อม fetch timestamp UTC, source URL และ SHA-256. [INFERRED — วิธี freeze ผ่าน builder]
IOC cache ก่อน run: path `[กรอก path ของ process USERPROFILE]`, size `[กรอก bytes หรือ absent]`, mtime `[กรอก UTC หรือ absent]`; หลัง run: `[กรอก size/mtime]`

## 8. บันทึกการเบี่ยงเบนจากโปรโตคอล

- **2026-10-11 — สถานะ C2 Trackers และผลต่อ URL:** จาก 10 feeds ที่กำหนดใน `src/integrations/threat_intel.py:786-832`, 9 feeds ตอบ HTTP 404 และมีเพียง `drb-ra` `IPC2s-30day.csv` ที่ตอบ HTTP 200 (เป็น IP list). หลักฐานใน repo ที่เก่าที่สุดที่พบคือ snapshot เวลา `2026-09-15T18:35:57Z` (`evidence/source_weights_2026-09-16/independent_external_proxy_holdout_overlap_2026-09-16.json:2,54-151`) และ `docs/CABTA_scope_ledger.md:1839-1840`. `montysecurity/C2-Tracker` ถูก archive (last push 2026-04-13) และไม่มี `data/` แล้ว. ประวัติ Git ระบุว่า URL ทั้ง 10 ถูกเพิ่มใน `e12e768` (2026-03-19); กฎ “no match + >=1 failed feed => unavailable” เพิ่มใน `21577ff` (2026-10-09). ก่อนหน้านั้น partial failures ถูกส่งกลับเป็น plain misses จึงเห็น `unavailable:false` ในผล holdout เก่า. **การตัดสินใจ:** ไม่เปลี่ยนระบบและไม่ซ่อม feed; ระบบที่ประเมินจึงยังเป็นระบบเดียวกับที่ให้ผล 91.0% และเป็นระบบตาม paper. ผลที่ต้องบันทึก: คาดว่า `c2_trackers` เป็น `unavailable=true` บน URL rows และ ThreatFox เป็น effective URL source; บันทึกจำนวน URL rows ที่ C2 unavailable และให้ overlap script เก็บ failed feed freezes โดยระบุว่า `scripts/eval/measure_url_overlap.py` มีสำเนา feed list ของตนเอง. Environment ของ run: `LLM_DGA_VLLM_CANARY_PERCENT=100`, `BTA_CONFIG` unset; LLM-DGA ไม่ส่งผลต่อ `threat_score` หรือ verdict.

- **2026-10-12 — เพิ่ม clean candidates หลังรอบแรก:** [VERIFIED — `evidence/independent_url_holdout_2026-10-11/build_tranco_manifest.json` (`counts_by_stage`)] รอบแรกใช้ 400 Tranco domains (seed `20261011`) ได้ 170 candidates; [VERIFIED — `evidence/independent_url_holdout_2026-10-11/label_clean_urls_vt_manifest.json` (`counts_by_stage`)] ผล VT คือ CLEAN 30, AMBIGUOUS 1, MALICIOUS 0, NO_REPORT (`http_404`) 139, SOURCE_ERROR 0. ตัวเลือกที่พิจารณาคือใช้ CLEAN 30 ที่มี, สุ่ม candidates เพิ่มด้วยกฎเดิม, หรือส่ง URL เดิมให้ VT สแกนใหม่; ไม่เลือกการสแกนใหม่เพราะเปลี่ยนความหมายของ label จาก “มีรายงานอยู่แล้ว” เป็นผลหลัง submit scan. **การตัดสินใจที่กำหนดไว้ก่อน eval:** สุ่มโดเมนต่อจากลำดับเดียวกันที่สร้างด้วย `random.Random(20261011)` โดยใช้ตำแหน่ง 401–800 (400 domains ที่ไม่ซ้ำกับ 400 แรก); สร้าง candidate ตามกฎเดิม (homepage → หนึ่งลิงก์ภายในโดเมนเดียวกันที่มี path/query เป็น deep URL ไม่ใช่ homepage) และใช้ VT 3-tier rule เดิมโดยไม่เปลี่ยน. เป้าหมายคือ CLEAN รวมประมาณ 60 เท่านั้น; กฎหยุดคือสุ่มเพิ่มครบ 400 domains แล้วหยุด ไม่หยุดเมื่อถึงจำนวน CLEAN และไม่สุ่มต่อ. Clean arm สุดท้าย = CLEAN รอบแรก 30 + CLEAN รอบสองเท่าที่ได้. Candidate รอบแรกใช้จากไฟล์ที่ freeze ไว้ ห้ามดึง homepage ใหม่. หากการดึงหรือ label รอบสองยังไม่เสร็จภายใน 2026-10-13 12:00 เวลาไทย (+07:00) ให้ใช้ CLEAN 30 รายการและบันทึก deviation เพิ่ม. ฝั่ง malicious ไม่เปลี่ยน (OpenPhish 100 + PhishTank 100); ห้ามแก้ระบบ, weights, thresholds หรือ config. การตัดสินใจนี้เกิดหลังเห็นผล VT รอบแรก แต่ก่อนรัน eval ใด ๆ บนชุดใหม่.

- **2026-10-12 — ผล clean รอบ 2 และจำนวนสุดท้าย:** [VERIFIED — `evidence/independent_url_holdout_2026-10-11/clean_round2_build/build_tranco_round2_manifest.json`, `clean_round2_vt/label_clean_urls_vt_manifest.json`, `clean_final/combine_clean_url_rounds_manifest.json` และ SHA-256 ของไฟล์ผลในหัวข้อ 7] รอบสองใช้ Tranco domains ตำแหน่ง 401–800 จำนวน 400 domains; builder บันทึก 188 candidates, 135 `homepage_fetch_failed`, 51 `homepage_http_error`, 26 `no_internal_deep_link`, 1 `candidate_shortfall` และ shortfall ต่อ target 300 เท่ากับ 112. Dedup candidates รอบสองกับไฟล์ `evidence/vt_independent_holdout_2026-09-25/holdout_labeled_221.json` (221 rows), `data/benchmark/benchmark_iocs_v2.json` (1,094), `data/benchmark/benchmark_iocs_v2_backup.json` (894), `data/benchmark/benchmark_iocs_v3_domain_independent.json` (908), `data/benchmark/benchmark_iocs_clean_additions_2026-09-22.json` (250) และ `data/benchmark/benchmark_iocs.json` (85) พบ exact-URL ซ้ำ 0 และ host ซ้ำ 0 กับแต่ละไฟล์; manifest เตือนว่า `evidence/vt_independent_holdout_2026-09-25/vt_holdout_scoring_input.json` ไม่มีอยู่ จึงตรวจ dedup กับไฟล์นั้นไม่ได้. VT รอบสอง (2026-10-12T07:54:55.614982Z–08:46:40.827463Z) ได้ CLEAN 26, AMBIGUOUS 2, MALICIOUS 0, NO_REPORT (`http_404`) 160, SOURCE_ERROR 0. รวม clean รอบ 1 และ 2 ได้ 56 แถว (30 + 26) ซึ่งต่ำกว่าเป้าหมายประมาณ 60; ใช้ 56 ตามกฎหยุดหลัง 400 domains เพิ่ม โดยไม่สุ่มต่อ. [VERIFIED — manifests รอบสองระบุ `script_git_commit=04587259476b21664e61ea0b0b348a5bdb48eab4` และ `script_git_dirty=true`.] สถานะ Git ที่แนบมากับหลักฐานขณะ pull แสดง `?? evidence/independent_url_holdout_2026-10-11/` เท่านั้น; ไม่พบหลักฐานยืนยัน helpdesk files เป็นสาเหตุของ dirty flag จึงไม่ระบุสาเหตุนั้น.

## 9. ข้อจำกัดที่ประกาศล่วงหน้า

- ครอบคลุมเฉพาะ URL
- C2 Trackers มี 10 feeds ตาม config; หลักฐานที่เก่าที่สุดใน repo (snapshot `2026-09-15T18:35:57Z`) บันทึก 9 feeds เป็น HTTP 404 และ `drb-ra` `IPC2s-30day.csv` เป็น HTTP 200 ซึ่งเป็น IP list. คาดว่า URL rows จะมี `c2_trackers unavailable=true`; ดังนั้น effective URL source ในสภาวะนี้คือ ThreatFox. ระบบไม่ถูกแก้หรือซ่อม feed เพื่อคงระบบที่ประเมินให้ตรงกับผล 91.0% และ paper (`evidence/source_weights_2026-09-16/independent_external_proxy_holdout_overlap_2026-09-16.json:2,54-151`; `docs/CABTA_scope_ledger.md:1839-1840`; `src/integrations/threat_intel.py:786-832`). `measure_url_overlap.py` เก็บ feed list แยกไว้เอง จึงต้องบันทึก failed feed freezes จาก script นั้นด้วย
- FeodoTracker, Spamhaus และ Tor exit nodes อาจตรงได้ผ่าน IP ของ URL host เท่านั้น; ระบบไม่ใช้แหล่งเหล่านี้กับ URL IOC. SSLBL เป็น SHA1-only และไม่ใช้กับ URL IOC. [VERIFIED — `src/integrations/threat_intel.py:1021-23, 1025-39, 1052-53`]
- แหล่ง malicious เป็นข้อมูล phishing เท่านั้น ซึ่งต่างจากประเภทภัยที่ 6 scoring sources เน้น (C2/malware) ผล recall ต่ำจึงอาจสะท้อนความไม่ตรงของประเภทภัยด้วย ไม่ใช่แค่คุณภาพของระบบ
- Clean URLs ในชุดนี้จำกัดเฉพาะ URL ที่ VirusTotal มี report อยู่แล้ว; รอบแรก 139/170 candidates ไม่มี report (`http_404`). ห้ามเขียนว่าสุ่มเอนไปทางเว็บยอดนิยม เพราะข้อมูล Tranco rank ของ URL ที่ได้ยังไม่ชัดพอ
- จำนวน clean ที่น้อยทำให้ช่วงความเชื่อมั่นของ Precision/FPR กว้าง; รายงาน Specificity คู่กับ Precision พร้อม Wilson 95% CI แยกกัน. หาก FP=0 ให้คำนวณขอบบนจากจำนวน clean สุดท้ายจริง ห้ามใส่ตัวเลขล่วงหน้า
- [INFERRED] ผลหลักด้าน recall บน malicious URL ไม่ขึ้นกับขนาด clean arm เพราะ recall คำนวณจากแถว MALICIOUS ซึ่งเป็น positive class
- [VERIFIED — `evidence/vt_independent_holdout_2026-09-25/holdout_labeled_221.json`; ตรวจ clean URL 23 แถว] clean URL 23 รายการใน holdout เดิมเป็น homepage (`https://{domain}/`), ต่างจากชุดนี้ที่เลือก deep URL; ห้ามนำมารวมเป็นตัวเลขเดียว
- ขนาดชุดจำกัด ช่วงความเชื่อมั่นกว้าง
- OpenPhish community feed มีเฉพาะ URL ที่ active ณ เวลาดึง ไม่สามารถสร้างชุดเดิมซ้ำได้นอกจากใช้ไฟล์ที่ freeze ไว้
- [INFERRED] คาดว่า URL recall อาจต่ำ เพราะ OpenPhish/PhishTank อยู่นอก scoring และ IOC type URL มีแหล่ง scoring ที่ applicable เพียง C2 Trackers + ThreatFox; นี่เป็นข้อคาดหมายจาก source applicability ไม่ใช่ผลการทดลอง

## 10. หมายเหตุเกี่ยวกับ holdout เดิม

- [VERIFIED — `scripts/adhoc/vt_holdout_batch3_build_candidates.py:29`; `src/integrations/threat_intel.py:598-609`] URL false negatives 9/14 รายการใน holdout เดิมเกิดจาก batch-3 builder lowercasing URL path ก่อน lookup ขณะที่ ThreatFox exact-match URL แบบ case-sensitive. ตัวเลขที่รายงานเดิม (91.0%, URL recall 30%) คงเดิม; หากมี corrected re-run ให้รายงานแยกเป็น builder-bug correction ไม่ใช้แทน headline
