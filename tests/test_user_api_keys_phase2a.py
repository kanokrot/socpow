from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import TEAM_LEAD, get_current_user
from src.web.routes import account_api_keys as key_routes
from src.web import user_api_keys
from src.web.visibility import serialize_analysis_job, _safe_result


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "src" / "db" / "migrations"
ROLES = (
    "SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter", TEAM_LEAD,
    "admin",
)


def _migration(filename: str):
    spec = importlib.util.spec_from_file_location(filename[:-3], MIGRATIONS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _database(path: Path) -> dict[str, int]:
    for filename in (
        "001_create_users.py", "002_add_username_and_admin_role.py",
        "004_add_team_lead_role.py", "010_add_access_requests.py",
        "013_create_api_keys.py", "014_add_user_api_keys.py",
    ):
        _migration(filename).migrate(str(path))
    ids = {}
    with sqlite3.connect(path) as connection:
        for index, role in enumerate(ROLES):
            cursor = connection.execute(
                "INSERT INTO users(email, username, password_hash, role, is_active) "
                "VALUES (?, ?, 'hash', ?, 1)",
                (f"user{index}@example.test", f"user{index}", role),
            )
            ids[role] = int(cursor.lastrowid)
        connection.commit()
    return ids


class AuditCapture:
    def __init__(self):
        self.entries = []

    def add_audit_entry(self, **kwargs):
        self.entries.append(kwargs)


def _app(user: dict | None, audit: AuditCapture | None = None) -> FastAPI:
    app = FastAPI()
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.state.agent_store = audit or AuditCapture()
    app.include_router(key_routes.router, prefix="/api/account")
    return app


def test_cipher_encrypt_decrypt_roundtrip(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", key.decode())
    cipher = user_api_keys.UserApiKeyCipher()
    ciphertext = cipher.encrypt("vt-secret")
    assert ciphertext != "vt-secret"
    assert cipher.decrypt(ciphertext) == "vt-secret"


@pytest.mark.parametrize("role", [role for role in ROLES if role != "admin"])
def test_non_admin_authenticated_roles_can_manage_own_keys(tmp_path, monkeypatch, role):
    ids = _database(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    user = {"id": ids[role], "role": role, "is_active": 1}
    with TestClient(_app(user)) as client:
        saved = client.put("/api/account/intel-keys/otx", json={"api_key": "secret-token"})
        listed = client.get("/api/account/intel-keys")
    assert saved.status_code == 200
    assert saved.json() == {"source": "otx", "configured": True}
    assert listed.status_code == 200
    assert {row["source"] for row in listed.json()["keys"]} == set(user_api_keys.ALLOWED_SOURCES)
    otx = next(row for row in listed.json()["keys"] if row["source"] == "otx")
    assert otx["configured"] is True
    assert otx["masked_suffix"] == "••••oken"


def test_admin_personal_key_endpoints_are_forbidden_without_changing_rows(tmp_path, monkeypatch):
    ids = _database(tmp_path / "auth.db")
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    user_api_keys.UserApiKeyStore().save(ids["admin"], "otx", "s" * 40)
    with sqlite3.connect(db_path) as connection:
        before_count = connection.execute(
            "SELECT COUNT(*) FROM user_api_keys WHERE user_id = ?", (ids["admin"],)
        ).fetchone()[0]
        before_ciphertext = connection.execute(
            "SELECT encrypted_key FROM user_api_keys WHERE user_id = ? AND source = 'otx'",
            (ids["admin"],),
        ).fetchone()[0]

    admin = {"id": ids["admin"], "role": "admin", "is_active": 1}
    with TestClient(_app(admin)) as client:
        listed = client.get("/api/account/intel-keys")
        saved = client.put("/api/account/intel-keys/otx", json={"api_key": "r" * 40})
        deleted = client.delete("/api/account/intel-keys/otx")

    with sqlite3.connect(db_path) as connection:
        after_count = connection.execute(
            "SELECT COUNT(*) FROM user_api_keys WHERE user_id = ?", (ids["admin"],)
        ).fetchone()[0]
        after_ciphertext = connection.execute(
            "SELECT encrypted_key FROM user_api_keys WHERE user_id = ? AND source = 'otx'",
            (ids["admin"],),
        ).fetchone()[0]
    assert listed.status_code == 403
    assert saved.status_code == 403
    assert deleted.status_code == 403
    assert (after_count == before_count and after_ciphertext == before_ciphertext) is True


def test_account_api_key_card_shows_disabled_message_and_three_sources():
    template = (ROOT / "templates" / "account.html").read_text(encoding="utf-8")
    script = (ROOT / "static" / "js" / "account_api_keys.js").read_text(encoding="utf-8")
    assert "Personal API keys are not enabled yet. Ask an administrator to enable them." in template
    assert "VirusTotal" in script and "AbuseIPDB" in script and "AlienVault OTX" in script
    assert "masked_suffix" in script


def test_missing_encryption_key_returns_503_for_save(tmp_path, monkeypatch):
    ids = _database(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.delenv("USER_API_KEY_ENCRYPTION_KEY", raising=False)
    user = {"id": ids[ROLES[0]], "role": ROLES[0], "is_active": 1}
    with TestClient(_app(user)) as client:
        listed = client.get("/api/account/intel-keys")
        response = client.put("/api/account/intel-keys/virustotal", json={"api_key": "secret"})
        deleted = client.delete("/api/account/intel-keys/virustotal")
    assert listed.status_code == 200
    assert listed.json() == {
        "enabled": False,
        "reason": "Personal API keys are not enabled on this server.",
    }
    assert response.status_code == 503
    assert deleted.status_code == 503


@pytest.mark.parametrize("source", ["threatfox", "unknown", "VirusTotal"])
def test_unknown_source_is_rejected(tmp_path, monkeypatch, source):
    ids = _database(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    user = {"id": ids[ROLES[0]], "role": ROLES[0], "is_active": 1}
    with TestClient(_app(user)) as client:
        response = client.put(f"/api/account/intel-keys/{source}", json={"api_key": "x"})
    assert response.status_code == 400


def test_owner_isolation_and_no_key_or_ciphertext_in_response_audit_or_logs(
    tmp_path, monkeypatch, caplog,
):
    ids = _database(tmp_path / "auth.db")
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    key = "owner-a-secret-token"
    audit_a = AuditCapture()
    user_a = {"id": ids[ROLES[0]], "role": ROLES[0], "is_active": 1}
    user_b = {"id": ids[ROLES[1]], "role": ROLES[1], "is_active": 1}
    caplog.set_level(logging.INFO)
    with TestClient(_app(user_a, audit_a)) as client_a:
        response = client_a.put("/api/account/intel-keys/virustotal", json={"api_key": key})
        list_response = client_a.get("/api/account/intel-keys")
        assert client_a.delete("/api/account/intel-keys/virustotal").status_code == 204
    # Re-save so the attempted operation by B cannot mask ownership behavior.
    with TestClient(_app(user_a)) as client_a:
        client_a.put("/api/account/intel-keys/virustotal", json={"api_key": key})
    with sqlite3.connect(db_path) as connection:
        ciphertext = connection.execute(
            "SELECT encrypted_key FROM user_api_keys WHERE user_id = ?", (ids[ROLES[0]],)
        ).fetchone()[0]
    with TestClient(_app(user_b)) as client_b:
        b_list = client_b.get("/api/account/intel-keys").json()
        b_delete = client_b.delete("/api/account/intel-keys/virustotal")
    assert response.status_code == 200
    assert list_response.status_code == 200
    assert key not in response.text and key not in list_response.text
    assert ciphertext not in response.text and ciphertext not in list_response.text
    assert not next(row for row in b_list["keys"] if row["source"] == "virustotal")["configured"]
    assert b_delete.status_code == 204
    assert not any(key in json.dumps(entry) or ciphertext in json.dumps(entry) for entry in audit_a.entries)
    assert all(set(entry["after_state"]) == {"user_id", "source", "action"} for entry in audit_a.entries)
    assert key not in caplog.text and ciphertext not in caplog.text


def test_payload_rejects_extra_fields_and_unauthenticated_is_401():
    with TestClient(_app(None)) as client:
        assert client.get("/api/account/intel-keys").status_code == 401
    user = {"id": 1, "role": "Threat Hunter", "is_active": 1}
    with TestClient(_app(user)) as client:
        response = client.put(
            "/api/account/intel-keys/otx", json={"api_key": "x" * 32, "url": "https://evil.test"}
        )
    assert response.status_code == 400


def test_extra_evidence_serializer_only_passes_allowlisted_summary():
    result = {
        "ioc": "example.test", "verdict": "clean", "threat_score": 0,
        "sources_checked": 4, "sources_flagged": 0,
        "extra_evidence": [
            {"source": "otx", "status": "available", "summary": {"pulses": 3, "api_key": "leak"}},
            {"source": "threatfox", "status": "available", "summary": {"pulses": 100}},
        ],
    }
    safe = _safe_result(result, detailed=False)
    assert safe["extra_evidence"] == [
        {"source": "otx", "status": "available", "summary": {"pulses": 3}}
    ]
    job = {"analysis_type": "ioc", "params": {"value": "example.test"}, "result": result}
    assert serialize_analysis_job(job)["extra_evidence"] == safe["extra_evidence"]


def test_cross_check_failure_returns_only_generic_status(monkeypatch):
    class Store:
        def keys_for_lookup(self, user_id):
            return {"otx": "secret-key"}
        def mark_used(self, user_id, source):
            pass

    async def fail(*args, **kwargs):
        raise TimeoutError("secret-key https://provider.invalid")

    monkeypatch.setattr(user_api_keys, "_provider_lookup", fail)
    evidence = asyncio.run(user_api_keys.cross_check_ioc("1.2.3.4", "ipv4", 7, Store()))
    assert evidence == [{"source": "otx", "status": "unavailable"}]
    assert "secret-key" not in json.dumps(evidence)


@pytest.mark.parametrize("lookup_fails", [False, True])
def test_flow_a_attaches_extra_evidence_without_changing_scored_fields(
    tmp_path, monkeypatch, lookup_fails,
):
    from src.tools import ioc_investigator
    from src.web.routes import analysis as analysis_routes

    ids = _database(tmp_path / "auth.db")
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    store = user_api_keys.UserApiKeyStore()
    store.save(ids[ROLES[0]], "otx", "per-user-secret")

    base_result = {
        "ioc": "1.2.3.4", "ioc_type": "ipv4", "threat_score": 24,
        "verdict": "suspicious", "coverage": 0.75,
        "sources_checked": 8, "sources_flagged": 2,
        "sources": {"static_a": {"score": 20}, "static_b": {"status": "ok"}},
        "llm_input": "fixed investigator input",
    }

    class FakeInvestigator:
        def __init__(self, *args, **kwargs):
            pass
        def set_progress_callback(self, callback):
            pass
        async def investigate(self, *args, **kwargs):
            return dict(base_result)

    class FakeManager:
        def __init__(self): self.completed = None
        def update_progress(self, *args, **kwargs): pass
        def complete_job(self, job_id, result, verdict, score):
            self.completed = (result, verdict, score)
        def fail_job(self, *args, **kwargs):
            pytest.fail("cross-check failure should not fail the investigation")

    monkeypatch.setattr(ioc_investigator, "IOCInvestigator", FakeInvestigator)
    monkeypatch.setattr(analysis_routes, "_load_config", lambda: {})
    if lookup_fails:
        async def provider_error(*args, **kwargs):
            raise TimeoutError("per-user-secret https://provider.invalid")
        monkeypatch.setattr(user_api_keys, "_provider_lookup", provider_error)
    else:
        async def provider_ok(source, api_key, ioc, ioc_type):
            assert api_key == "per-user-secret"
            return {"source": source, "status": "available", "summary": {"pulses": 5}}
        monkeypatch.setattr(user_api_keys, "_provider_lookup", provider_ok)

    manager = FakeManager()
    analysis_routes._run_ioc_analysis_bg(
        manager, "job-1", "1.2.3.4", "ipv4", user_id=ids[ROLES[0]],
    )
    assert manager.completed is not None
    result, verdict, score = manager.completed
    assert result["extra_evidence"] == [{
        "source": "otx",
        "status": "unavailable" if lookup_fails else "available",
        **({} if lookup_fails else {"summary": {"pulses": 5}}),
    }]
    assert verdict == base_result["verdict"]
    assert score == base_result["threat_score"]
    assert json.dumps({key: result[key] for key in base_result}, sort_keys=True) == json.dumps(
        base_result, sort_keys=True,
    )
