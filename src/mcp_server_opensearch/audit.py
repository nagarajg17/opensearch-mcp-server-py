# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Security audit logging for the OpenSearch MCP server.

Emits structured audit events (e.g. authorization decisions) to a **configurable
sink**. The sink is an interface so the destination can change without touching the
call sites:

- ``FileAuditSink``    -> append one JSON object per line (JSONL) to a file
- ``LoggingAuditSink`` -> emit via a dedicated ``audit`` logger (stderr / log pipeline)
- ``NoopAuditSink``    -> drop events (default when auditing is disabled)

Selection is env-driven via :func:`get_audit_sink`.

Environment variables
---------------------
- ``AUDIT_ENABLED``   : enable audit logging (default: off -> NoopAuditSink)
- ``AUDIT_SINK``      : ``file`` | ``logging`` | ``noop`` (default ``logging``)
- ``AUDIT_FILE_PATH`` : path for the file sink (default ``./audit.log``)
"""

import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)
_audit_logger = logging.getLogger('mcp_server_opensearch.audit')


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


@dataclass
class AuditEvent:
    """A single security audit record."""

    event_type: str  # e.g. "authz_decision", "authn"
    timestamp: str = field(default_factory=_utc_now)
    decision: str | None = None  # "allow" | "deny"
    principal: str | None = None  # token subject
    client_id: str | None = None  # token azp / client_id
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    action: str | None = None  # tool name
    resource: str | None = None  # e.g. "Index::my-index"
    reason: list[str] = field(default_factory=list)  # policy ids / diagnostics
    request_id: str | None = None
    client_name: str | None = None  # MCP client application name
    source_ip: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to a compact JSON object."""
        return json.dumps(asdict(self), default=str, separators=(',', ':'))


class AuditSink(ABC):
    """Interface for an audit destination.

    Concrete sinks MUST implement :meth:`emit`. ``emit`` must never raise — a failing
    audit sink should not break request handling; log and swallow instead.
    """

    @abstractmethod
    def emit(self, event: AuditEvent) -> None:
        """Record a single audit event."""
        raise NotImplementedError

    def close(self) -> None:
        """Release resources held by the sink (optional)."""
        return None


class NoopAuditSink(AuditSink):
    """Drops all audit events. Used when auditing is disabled."""

    def emit(self, event: AuditEvent) -> None:
        """Do nothing."""
        return None


class LoggingAuditSink(AuditSink):
    """Emits audit events as JSON via a dedicated ``audit`` logger."""

    def emit(self, event: AuditEvent) -> None:
        """Log the event as a JSON line at INFO."""
        try:
            _audit_logger.info(event.to_json())
        except Exception as e:  # never break the request path
            logger.error('LoggingAuditSink failed to emit audit event: %s', e)


class FileAuditSink(AuditSink):
    """Appends audit events as JSON lines (JSONL) to a file.

    Thread-safe (guarded by a lock) and flushed on every write for durability.
    """

    def __init__(self, path: str):
        """Open the audit file in append mode."""
        self._path = path
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        # Line-buffered append; created if missing.
        self._fh = open(path, 'a', encoding='utf-8')
        logger.info('Audit sink writing to file: %s', os.path.abspath(path))

    def emit(self, event: AuditEvent) -> None:
        """Append one JSON line and flush."""
        line = event.to_json()
        try:
            with self._lock:
                self._fh.write(line + '\n')
                self._fh.flush()
        except Exception as e:  # never break the request path
            logger.error('FileAuditSink failed to write audit event: %s', e)

    def close(self) -> None:
        """Close the underlying file handle."""
        try:
            with self._lock:
                self._fh.close()
        except Exception:
            pass


def get_audit_sink() -> AuditSink:
    """Build the configured AuditSink from environment variables."""
    if not _is_truthy(os.getenv('AUDIT_ENABLED')):
        logger.info('Audit logging disabled (AUDIT_ENABLED not set)')
        return NoopAuditSink()

    sink = os.getenv('AUDIT_SINK', 'logging').strip().lower()
    if sink == 'noop':
        return NoopAuditSink()
    if sink == 'logging':
        logger.info('Audit logging enabled: logging sink')
        return LoggingAuditSink()
    if sink == 'file':
        path = os.getenv('AUDIT_FILE_PATH', './audit.log')
        return FileAuditSink(path)

    raise ValueError(f'Unknown AUDIT_SINK: {sink!r} (expected file, logging, or noop)')
