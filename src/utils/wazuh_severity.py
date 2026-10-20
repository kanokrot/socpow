"""
Wazuh Severity Mapper - Blue Team Assistant (SOCPOW)

แปลง threat_score / verdict ของ SOCPOW ให้เป็น Wazuh-style 4-level severity
(LOW / MEDIUM / HIGH / CRITICAL) สำหรับใช้ตอน integrate กับ Wazuh หรือ
แสดงผลใน report โดยไม่แตะ verdict logic เดิมใน helpers.py หรือ
severity logic เดิมใน correlation.py เลย

ที่มา threshold: ใช้ scale เดียวกับ determine_verdict() ใน helpers.py
(70 / 40 / 1) แค่เปลี่ยน output label ให้ตรงกับ Wazuh convention
"""

from typing import Optional

# Verdict string (ที่ระบบมีอยู่แล้ว) -> Wazuh severity
VERDICT_TO_WAZUH = {
    "MALICIOUS": "CRITICAL",
    "SUSPICIOUS": "HIGH",
    "CLEAN": "LOW",
    "UNKNOWN": "LOW",
}

# correlation.py severity (critical/high/medium/low/info) -> Wazuh severity
CORRELATION_TO_WAZUH = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
}


def score_to_wazuh_severity(score: int) -> str:
    """
    Determine Wazuh-style 4-level severity directly from threat_score.
    Same thresholds as determine_verdict() in helpers.py.

    Args:
        score: Threat score (0-100)

    Returns:
        'CRITICAL' | 'HIGH' | 'LOW'
        (หมายเหตุ: MEDIUM จะไม่ถูกใช้จาก path นี้ เพราะ threshold เดิม
        ออกแบบมาเป็น 3 tier ไม่มีช่วงคะแนนที่ map เป็น MEDIUM ได้
        ถ้าต้องการ MEDIUM ให้ใช้ correlation_to_wazuh_severity() แทน)
    """
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    else:
        return "LOW"


def verdict_to_wazuh_severity(verdict: str) -> str:
    """
    Convert an existing verdict string (MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN)
    to Wazuh-style severity, without recomputing from score.

    Args:
        verdict: Output of determine_verdict()

    Returns:
        'CRITICAL' | 'HIGH' | 'LOW'
    """
    return VERDICT_TO_WAZUH.get((verdict or "").upper(), "LOW")


def correlation_to_wazuh_severity(correlation_severity: str) -> str:
    """
    Convert correlation.py's severity output (critical/high/medium/low/info)
    to Wazuh-style severity. This is the ONLY path that can produce MEDIUM,
    since correlation.py already has a 5-tier scale.

    Args:
        correlation_severity: Output of CorrelationEngine._assess_severity()

    Returns:
        'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    """
    return CORRELATION_TO_WAZUH.get((correlation_severity or "").lower(), "LOW")

def wazuh_level_to_severity(rule_level: int) -> str:
    """
    Wazuh rule.level (0-15) -> SOCPOW severity bucket.

    Threshold ยึดตาม Wazuh's own default significance cutoff
    (ossec.conf: email_alert_level=12 คือจุดที่ Wazuh เองถือว่า
    "significant enough to notify") ไม่ใช่ตัวเลขที่ SOCPOW คิดเอาเอง.

    Bucket:
      0-6   -> LOW      (informational / low-priority, ต่ำกว่า email threshold มาก)
      7-11  -> MEDIUM   (ควรตรวจสอบ แต่ยังไม่ถึงระดับ significant)
      12-13 -> HIGH     (Wazuh ถือว่า significant พอจะแจ้งเตือนแล้ว)
      14-15 -> CRITICAL (severe/critical ตาม Wazuh's own classification)

    Args:
        rule_level: Wazuh rule.level, 0-15

    Returns:
        'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

    Raises:
        ValueError: ถ้า rule_level อยู่นอกช่วง 0-15 (กัน alert ที่ format ผิด
        ไม่ให้หลุดเข้ามาเป็น severity เพี้ยนแบบเงียบๆ)
    """
    if not isinstance(rule_level, int) or not (0 <= rule_level <= 15):
        raise ValueError(
            f"Invalid Wazuh rule.level: {rule_level!r} (expected int 0-15)"
        )

    if rule_level >= 14:
        return "CRITICAL"
    elif rule_level >= 12:
        return "HIGH"
    elif rule_level >= 7:
        return "MEDIUM"
    else:
        return "LOW"