"""CIRCL public MISP feed integration.

This module intentionally uses the public feed export only.  IOC checks are
performed against an in-memory index; MISP REST API calls are not used.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Set

import aiohttp
import certifi

logger = logging.getLogger(__name__)

SOURCE_ID = "misp_circl_feed_osint"
DISPLAY_SOURCE = "MISP"
MANIFEST_URL = "https://www.circl.lu/doc/misp/feed-osint/manifest.json"
EVENT_URL = "https://www.circl.lu/doc/misp/feed-osint/{event_uuid}.json"

DEFAULT_CACHE_TTL = 3600
REFRESH_FAILURE_THRESHOLD = 3
REFRESH_COOLDOWN_SECONDS = 900
# Allow a small number of per-event failures while retaining the mostly fresh
# full-feed cache; larger degradation keeps retry/backoff state active.
MAX_ACCEPTABLE_FAILURE_RATIO = 0.10
MAX_EVENT_CONCURRENCY = 4

_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


class MISPFeed:
    """Cache and query the CIRCL public MISP feed without per-IOC network calls."""

    def __init__(self, config: Dict):
        self.ttl_seconds = config.get("timeouts", {}).get(
            "feed_cache_ttl", DEFAULT_CACHE_TTL
        )
        self.timeout = aiohttp.ClientTimeout(total=30)

        self._index: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
        }
        self._event_index: Dict[str, Dict[str, Set[str]]] = {}
        self._event_timestamps: Dict[str, int] = {}
        # The global cursor limits normal incremental refreshes.  The
        # per-event timestamps remain the retry-safe fallback for partial
        # cycles where an event failed after the cursor advanced.
        self._cursor_timestamp = 0
        self._pending_event_ids: Set[str] = set()
        self._manifest: Dict[str, Dict] = {}

        self.cache_fetched_at: Optional[str] = None
        self.latest_event_timestamp: Optional[int] = None
        self.last_successful_refresh: Optional[str] = None
        self.consecutive_refresh_failures = 0

        self._last_successful_refresh_epoch: Optional[float] = None
        self._next_refresh_at = 0.0
        self._circuit_open_until = 0.0
        self._refresh_task: Optional[asyncio.Task] = None
        self._refresh_lock = asyncio.Lock()

    @staticmethod
    def _normalize_type(misp_type: str) -> Optional[str]:
        if misp_type in {"ip-src", "ip-dst"}:
            return "ip"
        if misp_type in {"domain", "hostname"}:
            return "domain"
        if misp_type in {"url", "uri"}:
            return "url"
        if misp_type in {
            "md5",
            "sha1",
            "sha256",
            "sha224",
            "sha384",
            "sha512",
        } or misp_type.startswith("sha3-"):
            return "hash"
        return None

    @staticmethod
    def _lookup_type(ioc_type: str) -> Optional[str]:
        if ioc_type == "ipv4":
            return "ip"
        if ioc_type in {"md5", "sha1", "sha256", "hash"}:
            return "hash"
        if ioc_type in {"domain", "url"}:
            return ioc_type
        return None

    @staticmethod
    def _normalize_value(value: str, ioc_type: str) -> str:
        value = value.strip()
        if ioc_type in {"ip", "domain", "hash"}:
            return value.lower()
        return value

    def _cache_has_data(self) -> bool:
        return any(self._index[bucket] for bucket in self._index)

    def _feed_status(self) -> str:
        if not self._cache_has_data():
            return "unavailable"
        if self._last_successful_refresh_epoch is None:
            return "stale"
        age = time.time() - self._last_successful_refresh_epoch
        return "fresh" if age < self.ttl_seconds else "stale"

    def _parse_event(self, payload: Dict) -> Dict[str, Set[str]]:
        event = payload.get("Event", {})
        attributes = list(event.get("Attribute") or [])

        for obj in event.get("Object") or []:
            attributes.extend(obj.get("Attribute") or [])

        parsed: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
        }

        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            bucket = self._normalize_type(str(attribute.get("type", "")))
            value = attribute.get("value")
            if bucket and isinstance(value, str) and value.strip():
                parsed[bucket].add(self._normalize_value(value, bucket))

        return parsed

    async def _refresh_manifest(
        self, session: aiohttp.ClientSession
    ) -> Dict[str, Dict]:
        async with session.get(MANIFEST_URL) as response:
            if response.status != 200:
                raise RuntimeError(f"manifest returned HTTP {response.status}")
            manifest = await response.json(content_type=None)

        if not isinstance(manifest, dict):
            raise ValueError("MISP manifest is not an object")

        self._manifest = manifest
        return manifest

    async def _fetch_event(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        event_uuid: str,
        timestamp: int,
    ) -> tuple[str, int, Dict]:
        async with semaphore:
            async with session.get(EVENT_URL.format(event_uuid=event_uuid)) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"event {event_uuid} returned HTTP {response.status}"
                    )
                payload = await response.json(content_type=None)
                if not isinstance(payload, dict):
                    raise ValueError(f"event {event_uuid} is not a JSON object")
                return event_uuid, timestamp, payload

    def _remove_event_from_index(self, event_uuid: str) -> None:
        old_event = self._event_index.pop(event_uuid, {})
        for bucket, values in old_event.items():
            self._index[bucket].difference_update(values)
        self._event_timestamps.pop(event_uuid, None)

    def _apply_event(
        self,
        event_uuid: str,
        timestamp: int,
        payload: Dict,
    ) -> None:
        self._remove_event_from_index(event_uuid)
        parsed = self._parse_event(payload)
        self._event_index[event_uuid] = parsed
        self._event_timestamps[event_uuid] = timestamp
        self._pending_event_ids.discard(event_uuid)

        for bucket, values in parsed.items():
            self._index[bucket].update(values)

    def _record_refresh_failure(self) -> None:
        self.consecutive_refresh_failures += 1
        failure_number = self.consecutive_refresh_failures
        cooldown = min(
            3600,
            REFRESH_COOLDOWN_SECONDS * (2 ** max(0, failure_number - 1)),
        )
        self._next_refresh_at = time.time() + cooldown
        if failure_number >= REFRESH_FAILURE_THRESHOLD:
            self._circuit_open_until = self._next_refresh_at

    def _record_successful_refresh(self) -> None:
        refreshed_at = datetime.now(timezone.utc).isoformat()
        self.cache_fetched_at = refreshed_at
        self.last_successful_refresh = refreshed_at
        self._last_successful_refresh_epoch = time.time()
        self._cursor_timestamp = max(self._event_timestamps.values(), default=0)
        self.latest_event_timestamp = self._cursor_timestamp or None
        self.consecutive_refresh_failures = 0
        self._next_refresh_at = 0.0
        self._circuit_open_until = 0.0

    def _record_partial_cache_update(self) -> None:
        # Preserve usable metadata even when the cycle has some failed events.
        self.cache_fetched_at = datetime.now(timezone.utc).isoformat()
        self._cursor_timestamp = max(self._event_timestamps.values(), default=0)
        self.latest_event_timestamp = self._cursor_timestamp or None

    async def _refresh_events(self) -> None:
        async with self._refresh_lock:
            now = time.time()
            if now < self._next_refresh_at or now < self._circuit_open_until:
                return

            try:
                async with aiohttp.ClientSession(
                    timeout=self.timeout,
                    connector=aiohttp.TCPConnector(ssl=_SSL_CONTEXT),
                    headers={"User-Agent": "SOCPOW-MISPFeed/1.0"},
                ) as session:
                    manifest = await self._refresh_manifest(session)

                    manifest_entries = []
                    for event_uuid, metadata in manifest.items():
                        if not isinstance(metadata, dict):
                            continue
                        try:
                            timestamp = int(metadata.get("timestamp", 0) or 0)
                        except (TypeError, ValueError):
                            timestamp = 0
                        manifest_entries.append((event_uuid, timestamp))

                    current_ids = {event_uuid for event_uuid, _ in manifest_entries}
                    for removed_id in set(self._event_index) - current_ids:
                        self._remove_event_from_index(removed_id)

                    if not self._event_timestamps:
                        pending = manifest_entries
                    else:
                        pending = [
                            (event_uuid, timestamp)
                            for event_uuid, timestamp in manifest_entries
                            if (
                                event_uuid in self._pending_event_ids
                                or event_uuid not in self._event_timestamps
                                or timestamp > self._cursor_timestamp
                                or timestamp > self._event_timestamps[event_uuid]
                            )
                        ]

                    semaphore = asyncio.Semaphore(MAX_EVENT_CONCURRENCY)
                    results = await asyncio.gather(
                        *(
                            self._fetch_event(
                                session,
                                semaphore,
                                event_uuid,
                                timestamp,
                            )
                            for event_uuid, timestamp in pending
                        ),
                        return_exceptions=True,
                    )

                total = len(pending)
                failures = 0
                successes = 0
                for result in results:
                    if isinstance(result, Exception):
                        failures += 1
                        logger.warning("[MISP] event refresh failed: %s", result)
                        continue
                    event_uuid, timestamp, payload = result
                    self._apply_event(event_uuid, timestamp, payload)
                    successes += 1

                if successes:
                    self._record_partial_cache_update()

                failure_ratio = failures / total if total else 0.0
                if total == 0 or failure_ratio <= MAX_ACCEPTABLE_FAILURE_RATIO:
                    self._record_successful_refresh()
                else:
                    for event_uuid, _ in pending:
                        if event_uuid not in self._event_timestamps:
                            self._pending_event_ids.add(event_uuid)
                    self._record_refresh_failure()
                    logger.warning(
                        "[MISP] refresh degraded: %d/%d events failed (%.1f%%)",
                        failures,
                        total,
                        failure_ratio * 100,
                    )

            except Exception as exc:
                self._record_refresh_failure()
                logger.warning("[MISP] refresh cycle failed: %s", exc)

    def _schedule_refresh(self) -> None:
        now = time.time()
        if now < self._next_refresh_at or now < self._circuit_open_until:
            return
        if self._refresh_task and not self._refresh_task.done():
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        self._refresh_task = loop.create_task(self._refresh_events())

    async def check_misp(self, ioc: str, ioc_type: str) -> Dict:
        """Check the in-memory MISP index; never awaits network activity."""
        self._schedule_refresh()

        bucket = self._lookup_type(ioc_type)
        feed_status = self._feed_status()
        common = {
            "source": DISPLAY_SOURCE,
            "source_id": SOURCE_ID,
            "feed_status": feed_status,
            "latest_event_timestamp": self.latest_event_timestamp,
            "cache_fetched_at": self.cache_fetched_at,
            "last_successful_refresh": self.last_successful_refresh,
            "consecutive_refresh_failures": self.consecutive_refresh_failures,
        }

        if bucket is None:
            return {
                **common,
                "status": "➖",
                "found": False,
                "score": 0,
                "message": "IOC type not supported by MISP mapping",
            }

        normalized = self._normalize_value(ioc, bucket)
        found = normalized in self._index[bucket]
        return {
            **common,
            "status": "✓" if found else ("⚠" if feed_status != "fresh" else "✗"),
            "found": found,
            "score": 85 if found else 0,
            "message": (
                "IOC found in MISP feed cache"
                if found
                else "IOC not found in MISP feed cache"
            ),
        }
