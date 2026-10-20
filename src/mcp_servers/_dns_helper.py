"""Small, fail-soft DNS resolver shared by the MCP DNS tools.

The helper deliberately keeps the result object independent from the MCP
servers.  Callers decide how an empty answer or an exception maps to their
existing public response schema.
"""

from dataclasses import dataclass, field
import ipaddress
import os
import socket
import threading
import time
from typing import Optional

try:
    import dns.exception
    import dns.resolver
    import dns.reversename

    DNSPYTHON_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the fallback test
    dns = None
    DNSPYTHON_AVAILABLE = False


DEFAULT_FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8")
_LEGACY_DNS_SETTINGS = {
    "SOCPOW_DNS_TIMEOUT": "CABTA_DNS_TIMEOUT",
    "SOCPOW_DNS_TOTAL_TIMEOUT": "CABTA_DNS_TOTAL_TIMEOUT",
    "SOCPOW_DNS_FALLBACK": "CABTA_DNS_FALLBACK",
    "SOCPOW_DNS_FALLBACK_SERVERS": "CABTA_DNS_FALLBACK_SERVERS",
}
SYSTEM_UNHEALTHY_SECONDS = 60.0
DEFAULT_TIMEOUT_SECONDS = 3.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 6.0

_health_lock = threading.Lock()
_system_unhealthy_until = 0.0


@dataclass
class DNSQueryResult:
    """Normalized result for one DNS query."""

    answers: list[str]
    resolver: str
    status: str = "ok"
    error: Optional[str] = None
    attempted_resolvers: list[str] = field(default_factory=list)


def dns_available() -> bool:
    """Return whether dnspython was importable when this module loaded."""

    return DNSPYTHON_AVAILABLE


def _setting(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is not None:
        return value
    legacy_name = _LEGACY_DNS_SETTINGS.get(name)
    return os.getenv(legacy_name, default) if legacy_name else default


def _timeout_seconds() -> float:
    raw = _setting("SOCPOW_DNS_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT_SECONDS
    return max(0.1, value)


def _total_timeout_seconds() -> float:
    raw = _setting("SOCPOW_DNS_TOTAL_TIMEOUT", str(DEFAULT_TOTAL_TIMEOUT_SECONDS))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = DEFAULT_TOTAL_TIMEOUT_SECONDS
    return max(0.1, value)


def _fallback_enabled() -> bool:
    return _setting("SOCPOW_DNS_FALLBACK", "1").strip() != "0"


def fallback_servers() -> list[str]:
    raw = _setting("SOCPOW_DNS_FALLBACK_SERVERS", "")
    configured = [part.strip() for part in raw.split(",") if part.strip()]
    return configured or list(DEFAULT_FALLBACK_SERVERS)


def _system_is_unhealthy(now: Optional[float] = None) -> bool:
    """Return whether the system resolver failed within the last 60 seconds."""
    current = time.monotonic() if now is None else now
    with _health_lock:
        return current < _system_unhealthy_until


def _mark_system_unhealthy() -> None:
    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = time.monotonic() + SYSTEM_UNHEALTHY_SECONDS


def _mark_system_healthy() -> None:
    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = 0.0


def reset_health_cache() -> None:
    """Reset in-process resolver health; useful for isolated callers/tests."""

    global _system_unhealthy_until
    with _health_lock:
        _system_unhealthy_until = 0.0


def _normalized_name(name: str) -> str:
    return str(name).strip().lower().rstrip(".")


def _address_from_ptr_name(name: str) -> Optional[str]:
    normalized = _normalized_name(name)
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        pass
    if normalized.endswith(".in-addr.arpa"):
        octets = normalized[: -len(".in-addr.arpa")].split(".")
        if len(octets) == 4 and all(part.isdigit() for part in octets):
            try:
                return str(ipaddress.ip_address(".".join(reversed(octets))))
            except ValueError:
                return None
    return None


def fallback_allowed(name: str, record_type: str = "A", address: Optional[str] = None) -> bool:
    """Apply the privacy guard before any public fallback is attempted."""

    normalized = _normalized_name(name)
    rtype = record_type.upper()
    if rtype == "PTR":
        candidate = address or _address_from_ptr_name(normalized)
        if candidate:
            try:
                parsed = ipaddress.ip_address(candidate)
                if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
                    return False
            except ValueError:
                pass
    if "." not in normalized:
        return False
    return not normalized.endswith((".local", ".internal", ".lan", ".corp", ".home"))


def _terminal_exception(exc: Exception) -> bool:
    if not DNSPYTHON_AVAILABLE:
        return False
    return isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer))


def _retryable_exception(exc: Exception) -> bool:
    if not DNSPYTHON_AVAILABLE:
        return False
    retryable = (
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        OSError,
        socket.timeout,
        TimeoutError,
        ConnectionError,
    )
    return isinstance(exc, retryable)


def _resolver(nameserver: Optional[str] = None, timeout: Optional[float] = None):
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver is not None:
        resolver.nameservers = [nameserver]
    query_timeout = _timeout_seconds() if timeout is None else max(0.001, timeout)
    resolver.timeout = query_timeout
    resolver.lifetime = query_timeout
    return resolver


def _answer_strings(answer) -> list[str]:
    values = []
    for item in answer:
        value = getattr(item, "address", None)
        if value is None:
            value = str(item)
        values.append(str(value).rstrip("."))
    return values


def _query(
    resolver,
    name: str,
    record_type: str,
    timeout: Optional[float] = None,
) -> list[str]:
    query_timeout = _timeout_seconds() if timeout is None else max(0.001, timeout)
    answer = resolver.resolve(name, record_type, lifetime=query_timeout)
    return _answer_strings(answer)


def _result_for_exception(
    exc: Exception,
    resolver_name: str,
    attempted_resolvers: Optional[list[str]] = None,
) -> DNSQueryResult:
    attempted = list(attempted_resolvers or [resolver_name])
    if DNSPYTHON_AVAILABLE and isinstance(exc, dns.resolver.NXDOMAIN):
        return DNSQueryResult([], resolver_name, status="nxdomain", attempted_resolvers=attempted)
    if DNSPYTHON_AVAILABLE and isinstance(exc, dns.resolver.NoAnswer):
        return DNSQueryResult([], resolver_name, status="noanswer", attempted_resolvers=attempted)
    return DNSQueryResult(
        [],
        resolver_name,
        status="error",
        error=str(exc),
        attempted_resolvers=attempted,
    )


def resolve_record(
    name: str,
    record_type: str = "A",
    *,
    address: Optional[str] = None,
    timeout: Optional[float] = None,
) -> DNSQueryResult:
    """Resolve one record with a deadline across system and fallback servers.

    After a retryable system-resolver failure, the health cache skips the
    system resolver for 60 seconds and later queries start at fallback.
    """

    if not DNSPYTHON_AVAILABLE:
        return DNSQueryResult([], "nslookup", status="unavailable")

    normalized = _normalized_name(name)
    rtype = record_type.upper()
    fallback_on = _fallback_enabled()
    system_name = "system"
    per_query_timeout = _timeout_seconds() if timeout is None else max(0.1, float(timeout))
    deadline = time.monotonic() + _total_timeout_seconds()
    attempted_resolvers: list[str] = []
    def query_with_deadline(nameserver: Optional[str]) -> list[str]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise dns.exception.Timeout("DNS total timeout expired")
        query_timeout = min(per_query_timeout, remaining)
        return _query(
            _resolver(nameserver, timeout=query_timeout),
            normalized,
            rtype,
            timeout=query_timeout,
        )

    if not (fallback_on and _system_is_unhealthy()):
        attempted_resolvers.append(system_name)
        try:
            values = query_with_deadline(None)
            _mark_system_healthy()
            return DNSQueryResult(values, system_name, attempted_resolvers=attempted_resolvers)
        except Exception as exc:
            if _terminal_exception(exc):
                _mark_system_healthy()
                return _result_for_exception(exc, system_name, attempted_resolvers)
            if not _retryable_exception(exc):
                return _result_for_exception(exc, system_name, attempted_resolvers)
            _mark_system_unhealthy()
            if not fallback_on or not fallback_allowed(normalized, rtype, address):
                return _result_for_exception(exc, system_name, attempted_resolvers)

    if fallback_on and fallback_allowed(normalized, rtype, address):
        last_error: Optional[Exception] = None
        servers = fallback_servers()
        for server in servers:
            if deadline - time.monotonic() <= 0:
                break
            resolver_name = f"fallback:{server}"
            attempted_resolvers.append(resolver_name)
            try:
                values = query_with_deadline(server)
                _mark_system_healthy() if server == "system" else None
                return DNSQueryResult(
                    values,
                    resolver_name,
                    attempted_resolvers=attempted_resolvers,
                )
            except Exception as exc:
                if _terminal_exception(exc):
                    return _result_for_exception(exc, resolver_name, attempted_resolvers)
                last_error = exc
                if not _retryable_exception(exc):
                    return _result_for_exception(exc, resolver_name, attempted_resolvers)
        label = attempted_resolvers[-1] if attempted_resolvers else system_name
        return _result_for_exception(
            last_error or RuntimeError("DNS total timeout expired"),
            label,
            attempted_resolvers,
        )

    return DNSQueryResult(
        [],
        system_name,
        status="error",
        error="fallback disabled or restricted",
        attempted_resolvers=attempted_resolvers,
    )


def resolve_ptr(ip: str) -> DNSQueryResult:
    """Resolve an address through PTR while applying the private-network guard."""

    if not DNSPYTHON_AVAILABLE:
        return DNSQueryResult([], "nslookup", status="unavailable")
    try:
        ptr_name = dns.reversename.from_address(ip).to_text()
    except Exception as exc:
        return DNSQueryResult([], "system", status="error", error=str(exc))
    return resolve_record(ptr_name, "PTR", address=ip)


def combine_resolvers(labels: list[str]) -> str:
    """Choose one stable top-level resolver label for a multi-query result."""

    values = [label for label in labels if label]
    for label in values:
        if label.startswith("fallback:"):
            return label
    if "system" in values:
        return "system"
    if "nslookup" in values:
        return "nslookup"
    return "system"


def resolve_many(name: str, record_types: list[str], max_workers: int = 8):
    """Resolve record types concurrently and return results in input order."""

    from concurrent.futures import ThreadPoolExecutor

    if not record_types:
        return []
    workers = min(max_workers, len(record_types))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(resolve_record, name, rtype) for rtype in record_types]
        return [(rtype, future.result()) for rtype, future in zip(record_types, futures)]
