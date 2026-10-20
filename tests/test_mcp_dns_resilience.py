import json
import time
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from src.agent import mcp_client as mcp_client_module
from src.agent.mcp_client import MCPClientManager, MCPConnection, MCPServerConfig
from src.mcp_servers import _dns_helper


class FakeAnswer(list):
    pass


def _answer(value="203.0.113.10"):
    return FakeAnswer([SimpleNamespace(address=value)])


def _fake_resolver(monkeypatch, system_action, fallback_action=None, calls=None):
    calls = calls if calls is not None else []

    class Resolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, record_type, lifetime=None):
            calls.append((self.configure, tuple(self.nameservers), name, record_type))
            action = system_action if self.configure else fallback_action
            if isinstance(action, BaseException):
                raise action
            return action(name, record_type) if callable(action) else action

    monkeypatch.setattr(_dns_helper.dns.resolver, "Resolver", Resolver)
    _dns_helper.reset_health_cache()
    return calls


@pytest.mark.asyncio
async def test_stdio_child_gets_dns_env_without_parent_secret(monkeypatch):
    captured = {}

    class FakeParameters:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    class FakeOwner:
        def __init__(self, params):
            self.params = params

        async def start(self):
            return None

    monkeypatch.setenv("SOCPOW_DNS_TIMEOUT", "5")
    monkeypatch.setenv("MCP_PARENT_SECRET", "must-not-reach-child")
    monkeypatch.setattr("mcp.client.stdio.StdioServerParameters", FakeParameters)
    monkeypatch.setattr(mcp_client_module, "_StdioSessionOwner", FakeOwner)

    config = MCPServerConfig(
        name="dns-test",
        transport="stdio",
        command="python",
        args=["-m", "example_server"],
        env={"MCP_CONFIG_VALUE": "allowed"},
    )
    connection = MCPConnection(config=config)

    await MCPClientManager()._connect_stdio(connection)

    assert captured["env"]["SOCPOW_DNS_TIMEOUT"] == "5"
    assert captured["env"]["MCP_CONFIG_VALUE"] == "allowed"
    assert "MCP_PARENT_SECRET" not in captured["env"]


def test_system_timeout_uses_fallback(monkeypatch):
    calls = _fake_resolver(
        monkeypatch,
        dns.exception.Timeout(),
        lambda *_: _answer(),
    )
    result = _dns_helper.resolve_record("example.com", "A")
    assert result.answers == ["203.0.113.10"]
    assert result.resolver.startswith("fallback:")
    assert calls[0][0] is True
    assert any(not item[0] for item in calls)


def test_fallback_chain_respects_total_deadline(monkeypatch):
    clock = {"value": 100.0}
    lifetimes = []

    class Resolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, record_type, lifetime=None):
            lifetimes.append((tuple(self.nameservers), lifetime))
            clock["value"] += lifetime
            raise dns.exception.Timeout()

    monkeypatch.setenv("SOCPOW_DNS_TIMEOUT", "0.5")
    monkeypatch.setenv("SOCPOW_DNS_TOTAL_TIMEOUT", "0.7")
    monkeypatch.setenv("SOCPOW_DNS_FALLBACK_SERVERS", "1.1.1.1,8.8.8.8")
    monkeypatch.setattr(_dns_helper.time, "monotonic", lambda: clock["value"])
    monkeypatch.setattr(_dns_helper.dns.resolver, "Resolver", Resolver)
    _dns_helper.reset_health_cache()

    result = _dns_helper.resolve_record("example.com", "A")

    assert result.status == "error"
    assert sum(lifetime for _, lifetime in lifetimes) <= 0.7 + 1e-9
    assert len(lifetimes) == 2
    assert lifetimes[0][1] == 0.5
    assert lifetimes[1][1] <= 0.2 + 1e-9


def test_fallback_error_labels_last_attempted_server(monkeypatch):
    _fake_resolver(
        monkeypatch,
        dns.exception.Timeout(),
        dns.exception.Timeout(),
    )
    monkeypatch.setenv("SOCPOW_DNS_FALLBACK_SERVERS", "1.1.1.1,8.8.8.8")
    monkeypatch.setenv("SOCPOW_DNS_TOTAL_TIMEOUT", "6")

    result = _dns_helper.resolve_record("example.com", "A")

    assert result.resolver == "fallback:8.8.8.8"
    assert result.attempted_resolvers == [
        "system",
        "fallback:1.1.1.1",
        "fallback:8.8.8.8",
    ]


@pytest.mark.parametrize("exc", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
def test_terminal_dns_answer_does_not_use_fallback(monkeypatch, exc):
    calls = _fake_resolver(monkeypatch, exc, lambda *_: _answer())
    result = _dns_helper.resolve_record("example.com", "A")
    assert result.status in {"nxdomain", "noanswer"}
    assert not any(not item[0] for item in calls)


def test_system_health_cache_skips_then_expires(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(_dns_helper.time, "monotonic", lambda: now["value"])
    calls = _fake_resolver(monkeypatch, dns.exception.Timeout(), lambda *_: _answer())

    _dns_helper.resolve_record("example.com", "A")
    first_system_calls = sum(1 for item in calls if item[0])
    _dns_helper.resolve_record("example.com", "A")
    assert sum(1 for item in calls if item[0]) == first_system_calls

    now["value"] = 161.0
    _dns_helper.resolve_record("example.com", "A")
    assert sum(1 for item in calls if item[0]) == first_system_calls + 1


@pytest.mark.parametrize("name", ["host", "x.corp"])
def test_name_privacy_guard_blocks_fallback(monkeypatch, name):
    calls = _fake_resolver(monkeypatch, dns.exception.Timeout(), lambda *_: _answer())
    result = _dns_helper.resolve_record(name, "A")
    assert result.resolver == "system"
    assert not any(not item[0] for item in calls)


def test_ptr_privacy_guard_blocks_private_fallback(monkeypatch):
    calls = _fake_resolver(monkeypatch, dns.exception.Timeout(), lambda *_: _answer())
    result = _dns_helper.resolve_ptr("10.0.0.5")
    assert result.resolver == "system"
    assert not any(not item[0] for item in calls)


def test_fallback_can_be_disabled(monkeypatch):
    monkeypatch.setenv("SOCPOW_DNS_FALLBACK", "0")
    calls = _fake_resolver(monkeypatch, dns.exception.Timeout(), lambda *_: _answer())
    result = _dns_helper.resolve_record("example.com", "A")
    assert result.resolver == "system"
    assert not any(not item[0] for item in calls)


def test_dkim_queries_are_parallel(monkeypatch):
    from src.mcp_servers import osint_tools

    def delayed_query(name, timeout=3):
        time.sleep(0.05)
        return ["v=spf1" if "_dmarc" not in name else "v=DMARC1"], True, "system"

    monkeypatch.setattr(osint_tools, "_dns_query_txt_result", delayed_query)
    started = time.monotonic()
    result = json.loads(osint_tools.email_security_check("example.com"))
    elapsed = time.monotonic() - started
    assert set(result) == {"domain", "checks", "security_issues", "score", "resolver"}
    assert elapsed < 0.30


def test_import_error_keeps_nslookup_path(monkeypatch):
    from src.mcp_servers import osint_tools

    completed = SimpleNamespace(returncode=0, stdout='text = "v=spf1"\n')
    monkeypatch.setattr(osint_tools._dns_helper, "dns_available", lambda: False)
    monkeypatch.setattr(osint_tools.subprocess, "run", lambda *args, **kwargs: completed)
    lines, ok = osint_tools._dns_query_txt("example.com")
    assert ok is True
    assert lines


def test_txt_timeout_reaches_dns_helper(monkeypatch):
    from src.mcp_servers import osint_tools

    captured = {}

    def fake_resolve(name, record_type, *, timeout=None, **kwargs):
        captured.update(name=name, record_type=record_type, timeout=timeout)
        return _dns_helper.DNSQueryResult(["v=spf1"], "system")

    monkeypatch.setattr(osint_tools._dns_helper, "resolve_record", fake_resolve)

    lines, ok, resolver = osint_tools._dns_query_txt_result("example.com", timeout=4)

    assert captured == {
        "name": "example.com",
        "record_type": "TXT",
        "timeout": 4,
    }
    assert lines == ["v=spf1"]
    assert ok is True
    assert resolver == "system"


def test_schema_parity_plus_resolver(monkeypatch):
    from src.mcp_servers import network_tools, osint_tools

    successful = _dns_helper.DNSQueryResult(["203.0.113.10"], "system")
    monkeypatch.setattr(osint_tools._dns_helper, "resolve_record", lambda *args, **kwargs: successful)
    monkeypatch.setattr(osint_tools._dns_helper, "resolve_many", lambda name, types: [(rtype, successful) for rtype in types])
    monkeypatch.setattr(osint_tools._dns_helper, "resolve_ptr", lambda ip: _dns_helper.DNSQueryResult(["ptr.example.com"], "system"))
    monkeypatch.setattr(osint_tools._dns_helper, "dns_available", lambda: True)
    monkeypatch.setattr(network_tools._dns_helper, "dns_available", lambda: True)
    monkeypatch.setattr(network_tools._dns_helper, "resolve_many", lambda name, types: [(rtype, successful) for rtype in types])

    dns_result = json.loads(osint_tools.dns_resolve("example.com", "A"))
    ptr_result = json.loads(osint_tools.reverse_dns("203.0.113.10"))
    email_result = json.loads(osint_tools.email_security_check("example.com"))
    network_result = json.loads(network_tools.dns_lookup("example.com", "A"))

    assert set(dns_result) == {"domain", "records", "resolver"}
    assert set(ptr_result) == {"ip", "hostname", "aliases", "addresses", "resolver"}
    assert set(email_result) == {"domain", "checks", "security_issues", "score", "resolver"}
    assert set(network_result) == {"domain", "records", "resolver"}
