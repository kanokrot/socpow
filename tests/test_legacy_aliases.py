from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.agent import mcp_client
from src.agent.agent_loop import _validate_rag_reference
from src.integrations import threat_feed_sync
from src.mcp_servers import _dns_helper
from src.rag import rag_knowledge_base
from src.web import auth as auth_core
from src.web.page_auth import PageAuthMiddleware
from src.web.security import csrf_cookie, session_cookie


def test_session_cookie_accepts_only_current_and_explicit_legacy_names():
    assert session_cookie({"socpow_session": "new"}) == "new"
    assert session_cookie({"cabta_session": "legacy"}) == "legacy"
    assert session_cookie({"socpow_session": "new", "cabta_session": "legacy"}) == "new"
    assert session_cookie({"foo_session": "untrusted", "evil_session": "untrusted"}) is None


def test_csrf_cookie_accepts_only_current_and_explicit_legacy_names():
    assert csrf_cookie({"socpow_csrf": "new"}) == "new"
    assert csrf_cookie({"cabta_csrf": "legacy"}) == "legacy"
    assert csrf_cookie({"socpow_csrf": "new", "cabta_csrf": "legacy"}) == "new"
    assert csrf_cookie({"foo_csrf": "untrusted"}) is None


def test_unrecognized_session_cookie_does_not_authenticate_page():
    app = FastAPI()
    app.add_middleware(PageAuthMiddleware)

    @app.get("/private")
    async def private_page(request: Request):
        return {"user": getattr(request.state, "user", None)}

    with TestClient(app) as client:
        response = client.get(
            "/private", cookies={"foo_session": "not-a-session"}, follow_redirects=False
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fprivate"


def test_api_key_prefix_allowlist_and_rate_identifier():
    accepted = (
        "socpow_live_ABCDEFGH_secret123",
        "cabta_live_ABCDEFGH_secret123",
    )
    for key in accepted:
        assert auth_core._API_KEY_PATTERN.fullmatch(key)
        assert auth_core._api_key_rate_identifier(key) == "ABCDEFGH"

    rejected = (
        "evil_live_xxxxxxxx_yyy",
        "evil_live_ABCDEFGH_secret123",
        "socpow_live_SHORT_secret",
    )
    for key in rejected:
        assert auth_core._API_KEY_PATTERN.fullmatch(key) is None
        assert auth_core._api_key_rate_identifier(key) == "invalid"


def test_legacy_api_key_lookup_uses_legacy_database_prefix(monkeypatch):
    key = "cabta_live_ABCDEFGH_secret123"
    looked_up = []
    updated = []
    row = {
        "key_id": 7,
        "user_id": 2,
        "key_hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
        "scope": auth_core.API_KEY_SCOPE,
        "expires_at": int(time.time()) + 3600,
        "revoked_at": None,
        "id": 2,
        "email": "ir@example.test",
        "username": "ir",
        "role": "Incident Responder",
        "is_active": 1,
    }

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            if "WHERE api_keys.key_prefix = ?" in query:
                looked_up.extend(params)
                return SimpleNamespace(fetchone=lambda: row)
            updated.append((query, params))
            return SimpleNamespace(fetchone=lambda: None)

        def commit(self):
            pass

    monkeypatch.setattr(auth_core, "_connect", FakeConnection)
    auth_core.api_key_rate_limiter.clear("ABCDEFGH", "192.0.2.10")
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/playbooks/alert_triage/run",
        "raw_path": b"/api/playbooks/alert_triage/run",
        "root_path": "",
        "scheme": "http",
        "query_string": b"",
        "headers": [],
        "client": ("192.0.2.10", 1234),
        "server": ("testserver", 80),
    })

    user = auth_core._authenticate_api_key(key, request)

    assert looked_up == ["cabta_live_ABCDEFGH"]
    assert updated
    assert user["username"] == "ir"


def test_stdio_env_passes_only_named_dns_aliases_and_configured_env(monkeypatch):
    dns_values = {
        "SOCPOW_DNS_TIMEOUT": "1",
        "SOCPOW_DNS_TOTAL_TIMEOUT": "2",
        "SOCPOW_DNS_FALLBACK": "0",
        "SOCPOW_DNS_FALLBACK_SERVERS": "1.1.1.1",
        "CABTA_DNS_TIMEOUT": "3",
        "CABTA_DNS_TOTAL_TIMEOUT": "4",
        "CABTA_DNS_FALLBACK": "1",
        "CABTA_DNS_FALLBACK_SERVERS": "8.8.8.8",
    }
    for name, value in dns_values.items():
        monkeypatch.setenv(name, value)
    for name in ("FOO_DNS_TIMEOUT", "EVIL_DNS_FALLBACK", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(name, "must-not-leak")

    child_env = mcp_client.MCPClientManager._build_stdio_env({})

    for name, value in dns_values.items():
        assert child_env[name] == value
    assert "FOO_DNS_TIMEOUT" not in child_env
    assert "EVIL_DNS_FALLBACK" not in child_env
    from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS
    if "AWS_SECRET_ACCESS_KEY" not in DEFAULT_INHERITED_ENV_VARS:
        assert "AWS_SECRET_ACCESS_KEY" not in child_env


def test_dns_settings_prefer_socpow_then_explicit_legacy_then_defaults(monkeypatch):
    settings = (
        ("SOCPOW_DNS_TIMEOUT", "CABTA_DNS_TIMEOUT", _dns_helper._timeout_seconds, "1.25", "3.5", 1.25, 3.5, 3.0),
        ("SOCPOW_DNS_TOTAL_TIMEOUT", "CABTA_DNS_TOTAL_TIMEOUT", _dns_helper._total_timeout_seconds, "2.25", "4.5", 2.25, 4.5, 6.0),
        ("SOCPOW_DNS_FALLBACK", "CABTA_DNS_FALLBACK", _dns_helper._fallback_enabled, "0", "1", False, True, True),
        ("SOCPOW_DNS_FALLBACK_SERVERS", "CABTA_DNS_FALLBACK_SERVERS", _dns_helper.fallback_servers, "9.9.9.9", "8.8.4.4", ["9.9.9.9"], ["8.8.4.4"], ["1.1.1.1", "8.8.8.8"]),
    )
    for new_name, old_name, getter, new_value, old_value, expected_new, expected_old, default in settings:
        monkeypatch.delenv(new_name, raising=False)
        monkeypatch.delenv(old_name, raising=False)
        monkeypatch.setenv(new_name, new_value)
        assert getter() == expected_new
        monkeypatch.delenv(new_name)
        monkeypatch.setenv(old_name, old_value)
        assert getter() == expected_old
        monkeypatch.setenv(new_name, new_value)
        assert getter() == expected_new
        monkeypatch.delenv(new_name)
        monkeypatch.delenv(old_name)
        assert getter() == default

    monkeypatch.setenv("FOO_DNS_TIMEOUT", "0.2")
    assert _dns_helper._timeout_seconds() == 3.0


def test_threat_feed_sync_env_aliases_and_default(monkeypatch):
    monkeypatch.setattr(threat_feed_sync, "sys", SimpleNamespace(modules={}))
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("SOCPOW_THREAT_FEED_SYNC", raising=False)
    monkeypatch.delenv("CABTA_THREAT_FEED_SYNC", raising=False)
    monkeypatch.delenv("FOO_THREAT_FEED_SYNC", raising=False)
    assert threat_feed_sync.sync_enabled() is True

    monkeypatch.setenv("SOCPOW_THREAT_FEED_SYNC", "0")
    assert threat_feed_sync.sync_enabled() is False
    monkeypatch.delenv("SOCPOW_THREAT_FEED_SYNC")
    monkeypatch.setenv("CABTA_THREAT_FEED_SYNC", "0")
    assert threat_feed_sync.sync_enabled() is False
    monkeypatch.setenv("SOCPOW_THREAT_FEED_SYNC", "1")
    assert threat_feed_sync.sync_enabled() is True
    monkeypatch.delenv("SOCPOW_THREAT_FEED_SYNC")
    monkeypatch.delenv("CABTA_THREAT_FEED_SYNC")
    monkeypatch.setenv("FOO_THREAT_FEED_SYNC", "0")
    assert threat_feed_sync.sync_enabled() is True


def _fake_rag_client(monkeypatch, existing_names):
    class FakeCollection:
        def __init__(self, name):
            self.name = name

        def count(self):
            return 0

    class FakeClient:
        def __init__(self, path):
            self.path = path
            self.existing = set(existing_names)
            self.created = []
            self.requested = []

        def list_collections(self):
            return list(self.existing)

        def get_or_create_collection(self, *, name, **_kwargs):
            self.requested.append(name)
            if name not in self.existing:
                self.created.append(name)
                self.existing.add(name)
            return FakeCollection(name)

    clients = []

    def create_client(*, path):
        client = FakeClient(path)
        clients.append(client)
        return client

    monkeypatch.setattr(
        rag_knowledge_base.chromadb,
        "PersistentClient",
        create_client,
    )
    monkeypatch.setattr(
        rag_knowledge_base.embedding_functions,
        "SentenceTransformerEmbeddingFunction",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(rag_knowledge_base, "_CHROMADB_AVAILABLE", True)
    return clients


def test_rag_creates_only_current_collection_when_no_collection_exists(monkeypatch, tmp_path):
    clients = _fake_rag_client(monkeypatch, [])

    instance = rag_knowledge_base.RAGKnowledgeBase(persist_dir=str(tmp_path / "empty"))

    assert instance._collection.name == "socpow_knowledge_base"
    assert clients[0].created == ["socpow_knowledge_base"]


def test_rag_uses_existing_legacy_collection_without_creating(monkeypatch, tmp_path):
    clients = _fake_rag_client(monkeypatch, ["cabta_knowledge_base"])

    instance = rag_knowledge_base.RAGKnowledgeBase(persist_dir=str(tmp_path / "legacy"))

    assert instance._collection.name == "cabta_knowledge_base"
    assert clients[0].created == []


def test_rag_prefers_existing_current_collection_without_creating(monkeypatch, tmp_path):
    clients = _fake_rag_client(
        monkeypatch, ["socpow_knowledge_base", "cabta_knowledge_base"]
    )

    instance = rag_knowledge_base.RAGKnowledgeBase(persist_dir=str(tmp_path / "both"))

    assert instance._collection.name == "socpow_knowledge_base"
    assert clients[0].created == []


def test_custom_rag_collection_name_never_falls_back_to_legacy(monkeypatch, tmp_path):
    clients = _fake_rag_client(monkeypatch, ["cabta_knowledge_base"])

    instance = rag_knowledge_base.RAGKnowledgeBase(
        persist_dir=str(tmp_path / "custom"),
        collection_name="team_knowledge_base",
    )

    assert instance._collection.name == "team_knowledge_base"
    assert clients[0].created == ["team_knowledge_base"]
    assert "cabta_knowledge_base" not in clients[0].requested


def test_rag_provenance_accepts_only_current_and_explicit_legacy_schema():
    fields = {
        "citation_id": "test-citation",
        "knowledge_type": "attack_pattern",
        "source_name": "Test Source",
        "source_url": "https://example.test/source",
        "source_version": "1",
        "confidence": 90,
        "tlp": "TLP:CLEAR",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "revoked": False,
    }
    for schema in ("socpow-rag-provenance/1", "cabta-rag-provenance/1"):
        valid, reason = _validate_rag_reference({
            "text": "valid reference",
            "metadata": {**fields, "schema_version": schema},
        })
        assert valid, reason

    valid, reason = _validate_rag_reference({
        "text": "invalid reference",
        "metadata": {**fields, "schema_version": "foo-rag-provenance/1"},
    })
    assert valid is False
    assert reason == "unsupported schema_version"
