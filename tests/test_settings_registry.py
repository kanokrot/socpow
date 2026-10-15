from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.auth import get_current_user
from src.web.routes.config_api import router
from src.web.settings_registry import settings_sources
from src.scoring.intelligent_scoring import NON_API_SCORING_SOURCES


EXPECTED_CONFIG_KEYS = {
    "threatfox", "abusech", "virustotal", "abuseipdb", "shodan", "alienvault",
    "censys", "criminalip", "ipqualityscore", "phishtank", "ip2proxy", "greynoise",
    "pulsedive", "threatzone", "triage", "hybrid_analysis", "hybridanalysis", "anyrun",
    "joe_sandbox", "joesandbox",
}


def _client(user, monkeypatch, tmp_path, initial=None):
    config_path = tmp_path / "phase2_settings.yaml"
    config_path.write_text(yaml.safe_dump(initial or {}), encoding="utf-8")
    monkeypatch.setenv("BTA_CONFIG", str(config_path))
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: user
    app.include_router(router, prefix="/api/config")
    return TestClient(app), config_path


def _admin():
    return {"id": 1, "email": "admin@example.test", "role": "admin", "is_active": 1}


def test_registry_config_keys_are_unique_and_have_source_reads():
    entries = settings_sources()
    assert len({entry["id"] for entry in entries}) == len(entries)
    keys = {key for entry in entries for key in entry["config_keys"]}
    assert keys == EXPECTED_CONFIG_KEYS

    source_root = Path(__file__).parents[1] / "src"
    source_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in source_root.rglob("*.py")
        if path.name != "settings_registry.py"
    )
    assert all(key in source_text for key in EXPECTED_CONFIG_KEYS)


def test_only_threatfox_registry_entry_is_scoring_and_tracks_scoring_set():
    entries = settings_sources()
    scoring = [entry["id"] for entry in entries if entry["tier"] == "scoring"]
    assert scoring == ["threatfox"]
    assert "threatfox" in NON_API_SCORING_SOURCES


def test_sources_endpoint_masks_keys_and_accepts_alias_as_configured(monkeypatch, tmp_path):
    secret = "full-secret-api-key-value"
    client, _ = _client(_admin(), monkeypatch, tmp_path, {"api_keys": {"abusech": secret}})
    response = client.get("/api/config/settings/sources")
    assert response.status_code == 200
    payload = response.json()
    encoded = response.text
    assert secret not in encoded
    source = next(item for item in payload["sources"] if item["id"] == "threatfox")
    assert source["configured"] is True
    assert source["placeholder_key_names"] == []
    assert source["masked_preview"].startswith(secret[:4])
    assert secret[4:] not in encoded
    assert {item["tier"] for item in payload["sources"]} == {"scoring", "report", "sandbox"}


def test_source_status_uses_validator_and_never_previews_placeholder(monkeypatch, tmp_path):
    placeholder = "YOUR_API_KEY"
    valid = "livekey-abcdef012345"
    client, _ = _client(_admin(), monkeypatch, tmp_path, {
        "api_keys": {"virustotal": placeholder, "threatfox": "BURAYA_API_KEY", "abusech": valid, "shodan": 42},
    })

    response = client.get("/api/config/settings/sources")
    assert response.status_code == 200
    sources = {item["id"]: item for item in response.json()["sources"]}

    assert sources["virustotal"]["configured"] is False
    assert sources["virustotal"]["masked_preview"] == ""
    assert sources["virustotal"]["placeholder_key_names"] == ["virustotal"]
    assert sources["shodan"]["configured"] is False
    assert sources["shodan"]["masked_preview"] == ""
    assert placeholder not in response.text
    assert sources["threatfox"]["configured"] is True
    assert sources["threatfox"]["masked_preview"].startswith(valid[:4])
    assert valid[4:] not in response.text


def test_registry_uses_first_valid_alias_for_status_and_preview():
    entry = next(item for item in settings_sources({
        "threatfox": "REPLACE_ME",
        "abusech": "alias-key-abcdef0123",
    }) if item["id"] == "threatfox")

    assert entry["configured"] is True
    assert entry["masked_preview"].startswith("alia")


@pytest.mark.parametrize("value", ["YOUR_API_KEY_HERE", "API xxxxx", "<API_KEY>", "CHANGE_ME", "xxx-secret-token", "prefix_your_key", "token_here", "   "])
def test_custom_placeholders_are_not_configured_or_previewed(value, monkeypatch, tmp_path):
    client, _ = _client(_admin(), monkeypatch, tmp_path, {"api_keys": {"virustotal": value}})
    response = client.get("/api/config/settings/sources")
    assert response.status_code == 200
    source = next(item for item in response.json()["sources"] if item["id"] == "virustotal")
    assert source["configured"] is False
    assert source["masked_preview"] == ""
    assert source["placeholder_key_names"] == ["virustotal"]
    assert value not in response.text


def test_real_looking_keys_are_configured_and_previewed(monkeypatch, tmp_path):
    key = "livekey-abcdef0123456789"
    client, _ = _client(_admin(), monkeypatch, tmp_path, {"api_keys": {"virustotal": key}})
    source = next(item for item in client.get("/api/config/settings/sources").json()["sources"] if item["id"] == "virustotal")
    assert source["configured"] is True
    assert source["masked_preview"].startswith(key[:4])
    assert source["placeholder_key_names"] == []


@pytest.mark.parametrize("role", ["SOC Analyst Tier 1-2", "Incident Responder", "Threat Hunter", "Team Lead"])
def test_sources_endpoint_is_admin_only(role, monkeypatch, tmp_path):
    user = {"id": 2, "email": "user@example.test", "role": role, "is_active": 1}
    client, _ = _client(user, monkeypatch, tmp_path)
    assert client.get("/api/config/settings/sources").status_code == 403


def test_post_rejects_unknown_keys_and_analysis_values(monkeypatch, tmp_path):
    client, _ = _client(_admin(), monkeypatch, tmp_path)
    assert client.post("/api/config/settings", json={"api_keys": {"urlscan": "nope"}}).status_code == 400
    assert client.post("/api/config/settings", json={"analysis": {"enable_sandbox": True}}).status_code == 400
    assert client.post("/api/config/settings", json={"analysis": {"enable_llm": 1}}).status_code == 400


def test_post_saves_registered_keys_and_analysis_flags(monkeypatch, tmp_path):
    client, config_path = _client(_admin(), monkeypatch, tmp_path)
    response = client.post("/api/config/settings", json={
        "api_keys": {"threatfox": "secret-token"},
        "analysis": {"enable_llm": False, "enable_rag": True},
    })
    assert response.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["api_keys"]["threatfox"] == "secret-token"
    assert saved["analysis"] == {"enable_llm": False, "enable_rag": True}


def test_posting_alias_writes_primary_config_key(monkeypatch, tmp_path):
    client, config_path = _client(_admin(), monkeypatch, tmp_path)
    response = client.post("/api/config/settings", json={"api_keys": {"abusech": "shared-token"}})
    assert response.status_code == 200
    assert yaml.safe_load(config_path.read_text(encoding="utf-8"))["api_keys"] == {"threatfox": "shared-token"}


def test_clear_removes_all_aliases_but_empty_and_masked_values_do_not_clear(monkeypatch, tmp_path):
    client, config_path = _client(_admin(), monkeypatch, tmp_path, {"api_keys": {
        "hybrid_analysis": "canonical-secret", "hybridanalysis": "legacy-secret", "abusech": "abuse-secret",
    }})
    empty = client.post("/api/config/settings", json={"api_keys": {"abusech": ""}})
    assert empty.status_code == 200
    masked = client.post("/api/config/settings", json={"api_keys": {"abusech": "****"}})
    assert masked.status_code == 200
    clear = client.post("/api/config/settings", json={"clear_api_keys": ["hybrid_analysis"]})
    assert clear.status_code == 200
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["api_keys"] == {"abusech": "abuse-secret"}


def test_settings_template_has_three_tabs_registry_js_and_restart_text():
    root = Path(__file__).parents[1]
    template = (root / "templates" / "settings.html").read_text(encoding="utf-8").lower()
    template += (root / "templates" / "partials" / "settings_nav.html").read_text(encoding="utf-8").lower()
    assert "general" in template
    assert "intelligence sources" in template
    assert "system" in template
    assert "urlscan" not in template
    assert "gmail" not in template
    assert "var settings =" in template
    assert "/static/js/settings_sources.js" in template
    assert "settings are written to config.yaml; restart to apply." in template
    assert template.count('data-settings-tab=') == 3
    assert "@media (min-width: 992px)" in template
    assert "connecting wazuh? more" in template
    assert "info.config_path" in template and "info.data_dir" in template
    assert "{% if nav_admin and not on_account %}settings{% else %}my settings{% endif %}</h1>" in template
    assert "my settings" in template
    assert "admin only" in template
    assert 'href="/settings#general"' in template
    assert 'href="/settings#sources"' in template
    assert 'href="/settings#system"' in template
    assert "counts toward threat score" in template
    assert "shown in reports, never scored" in template
    assert "file analysis, outside ioc scoring" in template
    assert "no key needed:</strong> feodotracker, ssl blacklist, spamhaus, tor exit nodes, c2 trackers" in template
    assert "quota / plan" not in template
    assert "settings-sources-table thead th" in template
    source_labels = {entry["label"] for entry in settings_sources() if entry["tier"] == "sandbox"}
    assert source_labels == {"Triage", "Hybrid Analysis", "ANY.RUN", "Joe Sandbox"}


def test_source_status_labels_invalid_keys_as_not_set():
    source_js = (Path(__file__).parents[1] / "static" / "js" / "settings_sources.js").read_text(encoding="utf-8")
    assert "source.configured ? 'Configured' : 'Not set'" in source_js
    assert "source-status-icon not-set" in source_js
    assert "bi-check-circle-fill source-status-icon configured" in source_js


def test_system_info_api_returns_real_nonempty_paths(monkeypatch, tmp_path):
    client, config_path = _client(_admin(), monkeypatch, tmp_path, {
        "data_dir": "./configured-data",
        "cache": {"db_dir": "./cache-data"},
    })
    response = client.get("/api/config/info")
    assert response.status_code == 200
    info = response.json()
    assert Path(info["config_path"]).is_absolute()
    assert info["config_path"] == str(config_path.resolve())
    assert Path(info["data_dir"]).is_absolute()
    assert Path(info["data_dir"]) == (Path.cwd() / "configured-data").resolve()


def test_system_info_falls_back_to_database_directory(monkeypatch, tmp_path):
    client, _ = _client(_admin(), monkeypatch, tmp_path, {"cache": None})
    db_path = tmp_path / "auth-store" / "auth.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    response = client.get("/api/config/info")
    assert response.status_code == 200
    assert Path(response.json()["data_dir"]) == db_path.parent.resolve()


def test_full_app_gmail_router_is_default_off_and_can_be_enabled(monkeypatch, tmp_path):
    config_path = tmp_path / "app_config.yaml"
    config_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("BTA_CONFIG", str(config_path))
    monkeypatch.setenv("AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("USER_API_KEY_ENCRYPTION_KEY", "")
    monkeypatch.delenv("GMAIL_CONNECT_ENABLED", raising=False)

    from src.web.app import create_app

    disabled_app = create_app()
    disabled_app.dependency_overrides[get_current_user] = lambda: _admin()
    with TestClient(disabled_app) as client:
        sources = client.get("/api/config/settings/sources")
        personal_keys = client.get("/api/account/intel-keys")
        gmail_status = client.get("/api/settings/gmail/status")
    assert sources.status_code == 200
    assert {item["tier"] for item in sources.json()["sources"]} == {"scoring", "report", "sandbox"}
    assert personal_keys.status_code == 403
    assert gmail_status.status_code == 404

    monkeypatch.setenv("GMAIL_CONNECT_ENABLED", "true")
    enabled_app = create_app()
    enabled_app.dependency_overrides[get_current_user] = lambda: _admin()
    with TestClient(enabled_app) as client:
        enabled_status = client.get("/api/settings/gmail/status")
    assert enabled_status.status_code == 200
