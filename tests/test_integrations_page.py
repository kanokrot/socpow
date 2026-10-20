from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.app import _register_page_routes
from src.web.page_auth import PageAuthMiddleware
from tests.test_page_auth_guard import _session_cookie_for_role


ROOT = Path(__file__).resolve().parents[1]


def _integrations_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)
    _register_page_routes(app)
    return app


def _client_for_role(monkeypatch, tmp_path: Path, role: str) -> TestClient:
    token = _session_cookie_for_role(monkeypatch, tmp_path, role)
    client = TestClient(_integrations_app())
    client.cookies.set("socpow_session", token)
    return client


def test_integrations_page_role_access(monkeypatch, tmp_path: Path) -> None:
    for index, (role, expected_status) in enumerate((
        ("Incident Responder", 200),
        ("admin", 200),
        ("SOC Analyst Tier 1-2", 403),
    )):
        role_tmp_path = tmp_path / str(index)
        role_tmp_path.mkdir()
        client = _client_for_role(monkeypatch, role_tmp_path, role)
        with client:
            hub_response = client.get("/integrations", follow_redirects=False)
            wazuh_response = client.get("/integrations/wazuh", follow_redirects=False)

        assert hub_response.status_code == expected_status
        assert wazuh_response.status_code == expected_status
        if expected_status == 403:
            assert hub_response.json() == {"detail": "Insufficient permissions"}
            assert wazuh_response.json() == {"detail": "Insufficient permissions"}


def test_integrations_page_shows_hub_cards_and_provider_status_placeholders(
    monkeypatch, tmp_path: Path
) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/integrations")

    assert response.status_code == 200
    assert "Wazuh Alert Triage" in response.text
    assert 'href="/integrations/wazuh"' in response.text
    assert 'href="/api/integrations/wazuh/download"' in response.text
    assert "Gmail notifications" in response.text
    gmail_card = re.search(
        r'<article class="hub-card hub-compact-card">\s*'
        r'<div class="hub-card-top">.*?PLANNED.*?</div>\s*'
        r'<h3>Gmail notifications</h3>.*?</article>',
        response.text,
        re.DOTALL,
    )
    assert gmail_card is not None
    assert "<a " not in gmail_card.group(0) and "<button" not in gmail_card.group(0)
    assert "hubGmailStatus" not in response.text and "hubGmailDetail" not in response.text
    hub_js = (Path(__file__).parents[1] / "static" / "js" / "integrations_hub.js").read_text(encoding="utf-8")
    assert "/api/settings/gmail/status" not in hub_js
    assert "/static/js/integrations_hub.js?v=2" in response.text
    assert "MCP servers" in response.text
    assert "Threat intelligence" in response.text
    assert "Malware sandboxes" in response.text
    assert "Configured means a key passed format validation" in response.text
    assert 'id="hubThreatSummary"' in response.text
    assert 'id="hubSandboxSummary"' in response.text


def test_integrations_page_describes_circl_public_misp_feed_without_status(
    monkeypatch, tmp_path: Path
) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/integrations")

    assert response.status_code == 200
    assert "CIRCL public MISP feed" in response.text
    misp_card = re.search(
        r'<article class="hub-card hub-compact-card">(?:(?!</article>)[\s\S])*'
        r'<h3>CIRCL public MISP feed</h3>(?:(?!</article>)[\s\S])*</article>',
        response.text,
        re.DOTALL,
    )
    assert misp_card is not None
    assert "Configured" not in misp_card.group(0)


def test_incident_responder_hub_has_no_admin_settings_or_mcp_links(
    monkeypatch, tmp_path: Path
) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/integrations")

    assert response.status_code == 200
    assert 'href="/settings' not in response.text
    assert 'href="/mcp/servers"' not in response.text
    threat_card = re.search(
        r"<h3>Threat intelligence</h3>(.*?)</article>", response.text, re.DOTALL
    )
    assert threat_card is not None
    assert 'href="/account"' in threat_card.group(1)
    assert "System keys are managed by an administrator." in response.text
    assert "Counts system keys only. Personal keys in My settings are extra evidence and are not included." in response.text
    assert "Managed by an administrator" in response.text


def test_admin_integrations_hub_keeps_system_settings_link(monkeypatch, tmp_path: Path) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "admin")
    with client:
        response = client.get("/integrations")

    assert response.status_code == 200
    assert 'href="/settings#sources"' in response.text


def test_wazuh_setup_page_shows_bundle_details_without_version_or_copy(
    monkeypatch, tmp_path: Path
) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/integrations/wazuh")

    assert response.status_code == 200
    assert "Wazuh Alert Triage" in response.text
    assert 'href="/integrations">Integrations</a>' in response.text
    assert 'href="/api/integrations/wazuh/download"' in response.text
    for sample in sorted((ROOT / "deploy" / "wazuh" / "samples").glob("*.json")):
        assert sample.name in response.text
    assert "Version" not in response.text
    assert re.search(
        r"<button\b(?=[^>]*\bdisabled\b)[^>]*>[\s\S]*?\bCopy\b",
        response.text,
        re.IGNORECASE,
    ) is None


def test_integrations_status_returns_only_key_booleans_and_mcp_counts(monkeypatch, tmp_path: Path) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    client.app.state.config = {
        "api_keys": {
            "virustotal": "a" * 24,
            "threatzone": "YOUR_THREATZONE_API_KEY",
            "triage": "b" * 24,
        },
        "mcp_servers": [{"name": "configured-one"}, {"name": "configured-two"}],
    }

    class Store:
        def list_mcp_connections(self):
            return [{"name": "configured-two"}, {"name": "database-only"}]

    class MCPClient:
        def get_connection_status(self):
            return {
                "configured-one": {"connected": True},
                "configured-two": {"connected": False},
            }

    client.app.state.agent_store = Store()
    client.app.state.mcp_client = MCPClient()
    with client:
        response = client.get("/api/integrations/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["threat_intel"] == [
        {"name": "VirusTotal", "configured": True},
        {"name": "AbuseIPDB", "configured": False},
        {"name": "Shodan", "configured": False},
        {"name": "AlienVault OTX", "configured": False},
        {"name": "GreyNoise", "configured": False},
        {"name": "URLScan", "configured": None},
    ]
    assert payload["sandboxes"] == [
        {"name": "Triage", "configured": True},
        {"name": "ThreatZone", "configured": False},
        {"name": "Hybrid Analysis", "configured": False},
        {"name": "ANY.RUN", "configured": False},
    ]
    assert payload["mcp"] == {"configured_count": 3, "connected_count": 1}
    assert "gmail" not in payload
    assert "api_keys" not in payload
    assert "a" * 24 not in response.text

    del client.app.state.mcp_client
    with client:
        response_without_runtime = client.get("/api/integrations/status")
    assert response_without_runtime.json()["mcp"] == {
        "configured_count": 3,
        "connected_count": None,
    }


def test_integrations_status_is_unavailable_to_other_roles(monkeypatch, tmp_path: Path) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "SOC Analyst Tier 1-2")
    with client:
        response = client.get("/api/integrations/status")
    assert response.status_code == 403


def test_wazuh_download_contains_expected_bundle_files(monkeypatch, tmp_path: Path) -> None:
    client = _client_for_role(monkeypatch, tmp_path, "Incident Responder")
    with client:
        response = client.get("/api/integrations/wazuh/download")

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as bundle:
        actual_names = set(bundle.namelist())

    bundle_prefix = "socpow-wazuh-integration/"
    bundle_root = ROOT / "deploy" / "wazuh"
    expected_names = {
        f"{bundle_prefix}{name}"
        for name in ("README.md", "custom-socpow", "ossec.conf")
    }
    expected_names.update(
        f"{bundle_prefix}samples/{sample.name}"
        for sample in sorted((bundle_root / "samples").glob("*.json"))
    )
    assert actual_names == expected_names
