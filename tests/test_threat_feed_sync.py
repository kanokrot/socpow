from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.integrations import threat_feed_sync as feeds
from src.web.auth import get_current_user
from src.web.routes import dashboard


NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)


def _tf(ioc="8.8.8.8", **extra):
    return {
        "query_status": "ok",
        "data": [{
            "ioc": ioc,
            "ioc_type": "ipv4",
            "malware_printable": "Test malware",
            "threat_type_desc": "botnet",
            "confidence_level": 90,
            "first_seen_utc": "2026-10-08 00:00:00 UTC",
            **extra,
        }],
    }


def _feodo(address="1.2.3.4", **extra):
    return [{
        "ip_address": address,
        "port": "443",
        "malware": "Feodo",
        "first_seen": "2026-10-08 00:00:00",
        "last_online": "2026-10-09 00:00:00",
        **extra,
    }]


@pytest.mark.asyncio
async def test_normalize_threatfox_and_feodo_sanitize_skip_and_bound_fields():
    stamp = NOW.isoformat()
    tf_rows, skipped_tf = feeds.normalize_threatfox({
        "query_status": "ok",
        "data": [
            {**_tf()["data"][0], "ioc": " 8.8.8.8\x00 ", "malware_printable": "m" * 150,
             "threat_type_desc": "t" * 200},
            {"ioc": "https://example.test/a", "ioc_type": "url", "confidence_level": "bad"},
            None,
            {"ioc": 5},
        ],
    }, stamp)
    assert skipped_tf == 2
    assert len(tf_rows) == 2
    assert tf_rows[0]["ioc_value"] == "8.8.8.8"
    assert tf_rows[0]["malware"] == "m" * 100
    assert tf_rows[0]["threat_type"] == "t" * 160
    assert tf_rows[1]["ioc_type"] == "url"
    assert tf_rows[1]["confidence"] is None

    feodo_rows, skipped_feodo = feeds.normalize_feodo([
        _feodo("1.2.3.4", malware="A\x01B", country="DE")[0],
        {"ip_address": "5.6.7.8", "malware": "x" * 150},
        {},
        "malformed",
    ], stamp)
    assert skipped_feodo == 2
    assert feodo_rows[0]["ioc_value"] == "1.2.3.4:443"
    assert feodo_rows[0]["ioc_type"] == "ip:port"
    assert feodo_rows[0]["malware"] == "AB"
    assert feodo_rows[1]["ioc_value"] == "5.6.7.8"
    assert feodo_rows[1]["malware"] == "x" * 100
    assert feodo_rows[1]["country"] is None


def test_feodo_status_persists_and_legacy_schema_migrates(tmp_path):
    db = tmp_path / "legacy-feed.db"
    conn = feeds._connect(db)
    conn.execute("ALTER TABLE threat_feed_items DROP COLUMN status")
    conn.commit()
    conn.close()

    stamp = NOW.isoformat()
    rows, _skipped = feeds.normalize_feodo([
        {**_feodo("1.2.3.4")[0], "status": "online", "country": "US"},
        {**_feodo("5.6.7.8")[0], "status": "offline", "country": "GB"},
        {**_feodo("9.10.11.12")[0], "status": "unknown", "country": "JP"},
    ], stamp)
    feeds._store_success(db, "feodo", rows, stamp)

    conn = feeds._connect(db)
    try:
        statuses = dict(conn.execute(
            "SELECT ioc_value, status FROM threat_feed_items WHERE source='feodo'"
        ).fetchall())
    finally:
        conn.close()
    assert statuses == {
        "1.2.3.4:443": "online",
        "5.6.7.8:443": "offline",
        "9.10.11.12:443": None,
    }


@pytest.mark.asyncio
async def test_threatfox_country_enrichment_deduplicates_uses_db_cache_and_keeps_failures(tmp_path, monkeypatch):
    import threading

    db = tmp_path / "feeds.db"
    cached, _skipped = feeds.normalize_threatfox({
        "query_status": "ok",
        "data": [{
            "ioc": "1.1.1.1:443", "ioc_type": "ipv4:port", "country": "CA",
            "malware_printable": "Cached", "first_seen_utc": "2026-10-08",
        }],
    }, NOW.isoformat())
    feeds._store_success(db, "threatfox", cached, NOW.isoformat())
    payload = {
        "query_status": "ok",
        "data": [
            {"ioc": "1.1.1.1:80", "ioc_type": "ipv4:port", "malware_printable": "Cached", "first_seen_utc": "2026-10-08"},
            {"ioc": "8.8.8.8:80", "ioc_type": "ipv4:port", "malware_printable": "Lookup", "first_seen_utc": "2026-10-08"},
            {"ioc": "8.8.8.8:443", "ioc_type": "ipv4:port", "malware_printable": "Lookup", "first_seen_utc": "2026-10-08"},
            {"ioc": "9.9.9.9:443", "ioc_type": "ipv4:port", "malware_printable": "Failed", "first_seen_utc": "2026-10-08"},
        ],
    }
    calls = []
    main_thread = threading.get_ident()

    def lookup(ip):
        calls.append((ip, threading.get_ident()))
        return "us" if ip == "8.8.8.8" else None

    monkeypatch.setattr(feeds, "fetch_threatfox", lambda _keys: _async_value(payload))
    monkeypatch.setattr(feeds, "lookup_ip_country", lookup)
    monkeypatch.setattr(feeds.time, "sleep", lambda _seconds: None)
    state = await feeds.sync_source("threatfox", {}, db, now_fn=lambda: NOW + timedelta(minutes=1))

    assert state["status"] == "ok"
    assert [ip for ip, _thread_id in calls] == ["8.8.8.8", "9.9.9.9"]
    assert all(thread_id != main_thread for _ip, thread_id in calls)
    conn = feeds._connect(db)
    try:
        countries = dict(conn.execute(
            "SELECT ioc_value,country FROM threat_feed_items WHERE source='threatfox'"
        ).fetchall())
    finally:
        conn.close()
    assert countries["1.1.1.1:80"] == "CA"
    assert countries["8.8.8.8:80"] == "US"
    assert countries["8.8.8.8:443"] == "US"
    assert countries["9.9.9.9:443"] is None


@pytest.mark.asyncio
async def test_threatfox_country_enrichment_caps_lookups_per_sync(tmp_path, monkeypatch):
    import ipaddress

    db = tmp_path / "feeds.db"
    first_ip = ipaddress.ip_address("8.8.0.1")
    payload = {
        "query_status": "ok",
        "data": [{
            "ioc": f"{first_ip + index}:443", "ioc_type": "ipv4:port",
            "malware_printable": "Batch", "first_seen_utc": "2026-10-08",
        } for index in range(feeds.THREATFOX_COUNTRY_LOOKUP_LIMIT + 1)],
    }
    calls = []
    monkeypatch.setattr(feeds, "fetch_threatfox", lambda _keys: _async_value(payload))
    monkeypatch.setattr(feeds, "lookup_ip_country", lambda ip: calls.append(ip) or "US")
    monkeypatch.setattr(feeds.time, "sleep", lambda _seconds: None)

    result = await feeds.sync_source("threatfox", {}, db, now_fn=lambda: NOW)
    assert result["status"] == "ok"
    assert len(calls) == feeds.THREATFOX_COUNTRY_LOOKUP_LIMIT
    assert len(set(calls)) == feeds.THREATFOX_COUNTRY_LOOKUP_LIMIT


@pytest.mark.asyncio
async def test_upsert_idempotence_snapshot_deletion_and_retention(tmp_path, monkeypatch):
    db = tmp_path / "feeds.db"
    monkeypatch.setattr(feeds, "fetch_threatfox", lambda _keys: _async_value(_tf()))
    monkeypatch.setattr(feeds, "fetch_feodo", lambda: _async_value(_feodo()))
    config = {"api_keys": {"threatfox": "dummy-injected-valid-test-key"}}
    await feeds.sync_all(config, db, now_fn=lambda: NOW)
    await feeds.sync_all(config, db, now_fn=lambda: NOW + timedelta(minutes=2))
    assert len(feeds.get_items(db, 50)) == 2

    monkeypatch.setattr(feeds, "fetch_feodo", lambda: _async_value(_feodo("9.9.9.9")))
    await feeds.sync_source("feodo", config, db, now_fn=lambda: NOW + timedelta(days=1))
    feodo_items = [item for item in feeds.get_items(db, 50) if item["source"] == "feodo"]
    assert [item["ioc_value"] for item in feodo_items] == ["9.9.9.9:443"]

    conn = feeds._connect(db)
    try:
        conn.execute(
            "UPDATE threat_feed_items SET fetched_at=? WHERE source='threatfox'",
            ((NOW - timedelta(days=31)).isoformat(),),
        )
        conn.commit()
    finally:
        conn.close()
    monkeypatch.setattr(feeds, "fetch_threatfox", lambda _keys: _async_value(_tf("7.7.7.7")))
    await feeds.sync_source("threatfox", config, db, now_fn=lambda: NOW + timedelta(days=1))
    assert [item["ioc_value"] for item in feeds.get_items(db, 50) if item["source"] == "threatfox"] == ["7.7.7.7"]


async def _async_value(value):
    return value


def _install_mock_transport(monkeypatch, *, post_body, get_body=None, post_status=200):
    calls = []
    chunk_sizes = []

    class FakeContent:
        def __init__(self, body):
            self.body = body

        async def iter_chunked(self, chunk_size):
            for offset in range(0, len(self.body), chunk_size):
                chunk = self.body[offset:offset + chunk_size]
                chunk_sizes.append(len(chunk))
                yield chunk

    class FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self.content = FakeContent(body)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class FakeSession:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        def post(self, url, *, json, headers):
            calls.append({"method": "POST", "url": url, "body": json})
            return FakeResponse(post_status, post_body)

        def get(self, url):
            calls.append({"method": "GET", "url": url})
            body = get_body if get_body is not None else b"[]"
            return FakeResponse(200, body)

    monkeypatch.setattr(feeds.aiohttp, "ClientSession", FakeSession)
    return calls, chunk_sizes


@pytest.mark.asyncio
async def test_threatfox_normalizes_sorts_then_caps_newest_500(tmp_path, monkeypatch):
    indices = list(range(1500))
    random.Random(2026).shuffle(indices)
    rows = []
    for index in indices:
        seen = NOW - timedelta(minutes=1500 - index)
        rows.append({
            "ioc": f"host-{index}.example.test",
            "ioc_type": "domain",
            "first_seen": seen.strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
    rows.append({"ioc": "unparseable.example", "ioc_type": "domain", "first_seen": "not-a-time"})

    async def fetch(_keys):
        return {"query_status": "ok", "data": rows}

    monkeypatch.setattr(feeds, "fetch_threatfox", fetch)
    db = tmp_path / "feed.db"
    result = await feeds.sync_source("threatfox", {}, db, now_fn=lambda: NOW)
    assert result["status"] == "ok"

    conn = feeds._connect(db)
    try:
        stored = conn.execute(
            "SELECT ioc_value, first_seen FROM threat_feed_items WHERE source='threatfox' "
            "ORDER BY first_seen DESC"
        ).fetchall()
    finally:
        conn.close()
    expected = [f"host-{index}.example.test" for index in range(1499, 999, -1)]
    assert len(stored) == 500
    assert [row["ioc_value"] for row in stored] == expected
    newest_seen = (NOW - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S UTC")
    assert stored[0]["first_seen"] == newest_seen
    assert feeds._parse_time(stored[0]["first_seen"]) == NOW - timedelta(minutes=1)


@pytest.mark.asyncio
async def test_threatfox_request_uses_one_day_body_via_mock_transport(monkeypatch):
    calls, _chunk_sizes = _install_mock_transport(
        monkeypatch,
        post_body=json.dumps({"query_status": "ok", "data": []}).encode(),
    )
    result = await feeds.fetch_threatfox({"threatfox": "unit-fake-key-91abcdef"})
    assert result == {"query_status": "ok", "data": []}
    assert calls == [{
        "method": "POST",
        "url": feeds.THREATFOX_URL,
        "body": {"query": "get_iocs", "days": 1},
    }]


@pytest.mark.asyncio
async def test_oversized_threatfox_response_keeps_rows_and_feodo_syncs(tmp_path, monkeypatch):
    db = tmp_path / "feed.db"
    previous, _skipped = feeds.normalize_threatfox(_tf("old.example"), NOW.isoformat())
    feeds._store_success(db, "threatfox", previous, NOW.isoformat())
    too_large = b" " * (feeds.MAX_RESPONSE_BYTES + 200)
    calls, chunk_sizes = _install_mock_transport(
        monkeypatch,
        post_body=too_large,
        get_body=json.dumps(_feodo()).encode(),
    )
    states = await feeds.sync_all(
        {"api_keys": {"threatfox": "unit-fake-key-91abcdef"}}, db, now_fn=lambda: NOW + timedelta(hours=2)
    )
    threatfox = next(row for row in states if row["source"] == "threatfox")
    feodo = next(row for row in states if row["source"] == "feodo")
    assert threatfox["error_code"] == "response_too_large"
    assert threatfox["status"] == "response_too_large"
    assert [item["ioc_value"] for item in feeds.get_items(db, 50) if item["source"] == "threatfox"] == ["old.example"]
    assert feodo["status"] == "ok"
    assert [item["ioc_value"] for item in feeds.get_items(db, 50) if item["source"] == "feodo"] == ["1.2.3.4:443"]
    assert calls[0]["body"]["days"] == 1
    assert calls[1]["method"] == "GET"
    assert sum(chunk_sizes) > feeds.MAX_RESPONSE_BYTES
    assert max(chunk_sizes) <= 64 * 1024


@pytest.mark.asyncio
@pytest.mark.parametrize("body, expected", [
    (b"not-json", "parse_error"),
    (b'{"query_status":"ok","data":"provider error"}', "parse_error"),
])
async def test_invalid_json_and_string_data_are_parse_errors(tmp_path, monkeypatch, body, expected):
    calls, _chunk_sizes = _install_mock_transport(monkeypatch, post_body=body)
    state = await feeds.sync_source(
        "threatfox",
        {"api_keys": {"threatfox": "unit-fake-key-91abcdef"}},
        tmp_path / "feed.db",
        now_fn=lambda: NOW,
    )
    assert calls[0]["body"]["days"] == 1
    assert state["error_code"] == expected
    assert state["status"] == expected


@pytest.mark.parametrize(("ioc_type", "expected"), [
    ("ip:port", "ip:port"),
    ("domain", "domain"),
    ("url", "url"),
    ("md5_hash", "hash"),
    ("sha256_hash", "hash"),
    ("sha1_hash", "hash"),
    ("unrecognized_type", "other"),
    ("not_a_hash_type", "other"),
])
def test_threatfox_ioc_type_mapping(ioc_type, expected):
    payload = {"query_status": "ok", "data": [{"ioc": "unknown:123", "ioc_type": ioc_type}]}
    normalized, _skipped = feeds.normalize_threatfox(payload, NOW.isoformat())
    assert normalized[0]["ioc_type"] == expected


@pytest.mark.asyncio
async def test_missing_auth_key_does_not_block_feodo(tmp_path, monkeypatch):
    called = []

    async def no_key(_keys):
        called.append("threatfox")
        raise feeds.FeedFetchError("auth_key_missing")

    async def feodo():
        called.append("feodo")
        return _feodo()

    monkeypatch.setattr(feeds, "fetch_threatfox", no_key)
    monkeypatch.setattr(feeds, "fetch_feodo", feodo)
    states = await feeds.sync_all({}, tmp_path / "feed.db", now_fn=lambda: NOW)
    assert called == ["threatfox", "feodo"]
    assert next(row for row in states if row["source"] == "threatfox")["status"] == "auth_key_missing"
    assert next(row for row in states if row["source"] == "feodo")["status"] == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure, expected", [
    (feeds.FeedFetchError("http_401"), "http_401"),
    (feeds.FeedFetchError("timeout"), "timeout"),
    (ValueError("bad payload"), "parse_error"),
])
async def test_failure_keeps_rows_and_records_safe_code(tmp_path, monkeypatch, failure, expected):
    db = tmp_path / "feed.db"
    async def success(_keys):
        return _tf()
    monkeypatch.setattr(feeds, "fetch_threatfox", success)
    await feeds.sync_source("threatfox", {"api_keys": {}}, db, now_fn=lambda: NOW)
    prior = feeds.get_items(db, 50)

    async def failed(_keys):
        raise failure
    monkeypatch.setattr(feeds, "fetch_threatfox", failed)
    state = await feeds.sync_source("threatfox", {}, db, now_fn=lambda: NOW + timedelta(hours=2))
    assert feeds.get_items(db, 50) == prior
    assert state["error_code"] == expected
    assert state["status"] == expected


def test_due_weekly_and_retry_backoff(tmp_path):
    db = tmp_path / "feed.db"
    assert feeds.due("threatfox", db, now=NOW)
    conn = feeds._connect(db)
    try:
        conn.execute("INSERT INTO threat_feed_state VALUES(?,?,?,?,?,?)", (
            "threatfox", (NOW - timedelta(hours=2)).isoformat(),
            (NOW - timedelta(days=6)).isoformat(), "ok", None, 0,
        ))
        conn.commit()
    finally:
        conn.close()
    assert not feeds.due("threatfox", db, now=NOW)
    conn = feeds._connect(db)
    try:
        conn.execute("UPDATE threat_feed_state SET last_attempt_at=?,last_success_at=? WHERE source='threatfox'", (
            (NOW - timedelta(hours=2)).isoformat(), (NOW - timedelta(days=7)).isoformat(),
        ))
        conn.commit()
    finally:
        conn.close()
    assert feeds.due("threatfox", db, now=NOW)
    conn = feeds._connect(db)
    try:
        conn.execute("UPDATE threat_feed_state SET last_attempt_at=?,last_success_at=NULL WHERE source='threatfox'", (
            (NOW - timedelta(minutes=30)).isoformat(),
        ))
        conn.commit()
    finally:
        conn.close()
    assert not feeds.due("threatfox", db, now=NOW)


def _client(tmp_path, role="SOC Analyst Tier 1-2"):
    app = FastAPI()
    app.state.threat_feed_db_path = tmp_path / "feed.db"
    app.state.config = {"api_keys": {}}
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 7, "email": "feed@test", "username": "feed", "role": role, "is_active": 1,
    }
    app.include_router(dashboard.router, prefix="/api/dashboard")
    return app, TestClient(app)


def test_get_endpoint_roles_items_and_limit_clamp(tmp_path):
    feeds._store_success(tmp_path / "feed.db", "feodo", feeds.normalize_feodo([
        _feodo(str(index), port="80")[0] for index in range(60)
    ], NOW.isoformat())[0], NOW.isoformat())
    _app, client = _client(tmp_path)
    with client:
        response = client.get("/api/dashboard/threat-feed?limit=100")
    assert response.status_code == 200
    assert len(response.json()["items"]) == 50
    assert {"items", "sources"} == response.json().keys()

    _app, denied = _client(tmp_path, "Viewer")
    with denied:
        assert denied.get("/api/dashboard/threat-feed").status_code == 403

    no_auth = FastAPI()
    no_auth.state.threat_feed_db_path = tmp_path / "feed.db"
    no_auth.include_router(dashboard.router, prefix="/api/dashboard")
    with TestClient(no_auth) as anonymous:
        assert anonymous.get("/api/dashboard/threat-feed").status_code in {401, 403}


def test_post_sync_admin_non_admin_and_busy_lock(tmp_path, monkeypatch):
    async def threatfox(_keys):
        raise feeds.FeedFetchError("auth_key_missing")
    async def feodo():
        return _feodo()
    monkeypatch.setattr(feeds, "fetch_threatfox", threatfox)
    monkeypatch.setattr(feeds, "fetch_feodo", feodo)
    _app, admin = _client(tmp_path, "admin")
    with admin:
        response = admin.post("/api/dashboard/threat-feed/sync")
    assert response.status_code == 200
    assert len(response.json()["sources"]) == 2

    _app, user = _client(tmp_path, "Threat Hunter")
    with user:
        assert user.post("/api/dashboard/threat-feed/sync").status_code == 403

    _app, busy = _client(tmp_path, "admin")
    async def locked_request():
        await feeds.SYNC_LOCK.acquire()
        try:
            with busy:
                return busy.post("/api/dashboard/threat-feed/sync")
        finally:
            feeds.SYNC_LOCK.release()
    response = asyncio.run(locked_request())
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_scheduler_guard_and_loop_cancellation(monkeypatch):
    assert feeds.sync_enabled() is False
    calls = []
    async def fake_sleep(_seconds):
        calls.append(_seconds)
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await feeds.run_sync_loop(type("App", (), {"state": type("State", (), {"config": {}})()})(), sleep=fake_sleep)
    assert calls == [60]


@pytest.mark.asyncio
async def test_fetch_auth_key_missing_fails_before_http(monkeypatch):
    class NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("HTTP session must not be constructed without a key")
    monkeypatch.setattr(feeds.aiohttp, "ClientSession", NoNetwork)
    with pytest.raises(feeds.FeedFetchError) as exc:
        await feeds.fetch_threatfox({})
    assert exc.value.code == "auth_key_missing"
