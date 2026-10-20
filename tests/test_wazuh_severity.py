"""
Unit tests for src/utils/wazuh_severity.py

ครอบคลุมทั้ง 3 ฟังก์ชัน:
- score_to_wazuh_severity()      : SOCPOW threat_score -> Wazuh label (export)
- verdict_to_wazuh_severity()    : SOCPOW verdict string -> Wazuh label (export)
- wazuh_level_to_severity()      : Wazuh rule.level -> SOCPOW bucket (import)

หมายเหตุ: ฟังก์ชัน import (wazuh_level_to_severity) คือตัวที่ยังไม่มี
production caller เพราะไม่มี webhook endpoint รับ Wazuh alert
(ยืนยันด้วย grep แบบ negative evidence แล้ว — ดู capability gap doc)
Test ชุดนี้ทำให้ครบเพื่อพิสูจน์ correctness ของ mapping logic ล่วงหน้า
ก่อนมี endpoint จริง ไม่ใช่เพื่อ verify integration ที่ยังไม่มีอยู่
"""

import pytest
from src.utils.wazuh_severity import (
    score_to_wazuh_severity,
    verdict_to_wazuh_severity,
    wazuh_level_to_severity,
    VERDICT_TO_WAZUH,
    CORRELATION_TO_WAZUH,
)


# ====================================================================== #
#  score_to_wazuh_severity() — SOCPOW score (0-100) -> Wazuh label
# ====================================================================== #

class TestScoreToWazuhSeverity:

    @pytest.mark.parametrize("score,expected", [
        (100, "CRITICAL"),
        (70, "CRITICAL"),   # boundary: exactly at MALICIOUS threshold
        (69, "HIGH"),       # boundary: one below
        (40, "HIGH"),       # boundary: exactly at SUSPICIOUS threshold
        (39, "LOW"),        # boundary: one below
        (1, "LOW"),
        (0, "LOW"),
    ])
    def test_score_boundaries(self, score, expected):
        assert score_to_wazuh_severity(score) == expected

    def test_never_returns_medium(self):
        """
        เอกสารยืนยัน limitation: score-based path ไม่มีทาง return MEDIUM
        เพราะ threshold เดิม (70/40/1) เป็น 3-tier ไม่ใช่ 4-tier
        """
        results = {score_to_wazuh_severity(s) for s in range(0, 101)}
        assert "MEDIUM" not in results


# ====================================================================== #
#  verdict_to_wazuh_severity() — SOCPOW verdict string -> Wazuh label
# ====================================================================== #

class TestVerdictToWazuhSeverity:

    @pytest.mark.parametrize("verdict,expected", [
        ("MALICIOUS", "CRITICAL"),
        ("SUSPICIOUS", "HIGH"),
        ("CLEAN", "LOW"),
        ("UNKNOWN", "LOW"),
        ("malicious", "CRITICAL"),   # case-insensitive
        ("Suspicious", "HIGH"),      # mixed case
    ])
    def test_known_verdicts(self, verdict, expected):
        assert verdict_to_wazuh_severity(verdict) == expected

    @pytest.mark.parametrize("bad_input", [
        "SPAM",       # documented gap: not implemented in determine_verdict()
        "RANSOMWARE", # documented gap: not implemented in determine_verdict()
        "GARBAGE",
        "",
        None,
    ])
    def test_unknown_or_undocumented_verdicts_fallback_to_low(self, bad_input):
        """
        SPAM/RANSOMWARE ไม่มีจริงใน determine_verdict() (ยืนยันจาก helpers.py)
        ดังนั้นควร fallback เป็น LOW อย่างปลอดภัย ไม่ throw exception
        """
        assert verdict_to_wazuh_severity(bad_input) == "LOW"

    def test_mapping_dict_has_exactly_documented_keys(self):
        """กัน silent drift ถ้ามีคนเพิ่ม verdict ใหม่ใน helpers.py แต่ลืมอัปเดตที่นี่"""
        assert set(VERDICT_TO_WAZUH.keys()) == {
            "MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"
        }


# ====================================================================== #
#  correlation_to_wazuh_severity() — correlation.py severity -> Wazuh label
# ====================================================================== #

class TestCorrelationToWazuhSeverity:

    @pytest.mark.parametrize("sev,expected", [
        ("critical", "CRITICAL"),
        ("high", "HIGH"),
        ("medium", "MEDIUM"),   # only path that produces MEDIUM
        ("low", "LOW"),
        ("info", "LOW"),
        ("CRITICAL", "CRITICAL"),  # case-insensitive
    ])
    def test_known_severities(self, sev, expected):
        from src.utils.wazuh_severity import correlation_to_wazuh_severity
        assert correlation_to_wazuh_severity(sev) == expected

    def test_medium_only_reachable_from_correlation_path(self):
        """
        ยืนยัน architectural fact: MEDIUM ไม่มีทางมาจาก verdict/score path
        มีแค่ correlation path เดียวเท่านั้นที่คืน MEDIUM ได้
        """
        from src.utils.wazuh_severity import correlation_to_wazuh_severity
        assert correlation_to_wazuh_severity("medium") == "MEDIUM"
        assert "MEDIUM" not in {
            score_to_wazuh_severity(s) for s in range(0, 101)
        }
        assert "MEDIUM" not in VERDICT_TO_WAZUH.values()


# ====================================================================== #
#  wazuh_level_to_severity() — Wazuh rule.level (0-15) -> SOCPOW bucket
#  (import direction — no production caller yet, see capability gap doc)
# ====================================================================== #

class TestWazuhLevelToSeverity:

    @pytest.mark.parametrize("level,expected", [
        (0, "LOW"), (6, "LOW"),           # boundary: top of LOW
        (7, "MEDIUM"), (11, "MEDIUM"),    # boundary: top of MEDIUM
        (12, "HIGH"), (13, "HIGH"),       # boundary: top of HIGH
        (14, "CRITICAL"), (15, "CRITICAL"),
    ])
    def test_level_boundaries(self, level, expected):
        assert wazuh_level_to_severity(level) == expected

    def test_default_email_alert_level_maps_to_high(self):
        """
        Wazuh's own default email_alert_level=12 ควร map เป็น HIGH
        (จุดที่ Wazuh เองถือว่า "significant enough to notify")
        นี่คือ sanity check ว่า threshold ยึดตาม Wazuh semantics จริง
        ไม่ใช่ตัวเลขที่ SOCPOW เดาเอาเอง
        """
        assert wazuh_level_to_severity(12) == "HIGH"

    @pytest.mark.parametrize("bad_level", [16, -1, 100, -100])
    def test_out_of_range_raises_value_error(self, bad_level):
        with pytest.raises(ValueError):
            wazuh_level_to_severity(bad_level)

    @pytest.mark.parametrize("bad_type", [None, "12", 12.5, [12], {}])
    def test_non_int_raises_value_error(self, bad_type):
        """
        กัน alert ที่ format ผิด (เช่น Wazuh ส่ง level มาเป็น string)
        ไม่ให้ silent fallback เป็น LOW แบบเงียบๆ — ต้อง fail ชัดเจน
        """
        with pytest.raises(ValueError):
            wazuh_level_to_severity(bad_type)

    def test_all_16_levels_produce_valid_bucket(self):
        """สุขภาพโดยรวม: ทุก level 0-15 ต้อง map ได้ ไม่มี gap"""
        valid_buckets = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for level in range(0, 16):
            assert wazuh_level_to_severity(level) in valid_buckets