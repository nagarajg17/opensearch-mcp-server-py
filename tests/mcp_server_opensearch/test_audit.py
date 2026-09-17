# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the audit module."""

import json
import pytest
from mcp_server_opensearch.audit import (
    AuditEvent,
    AuditSink,
    FileAuditSink,
    LoggingAuditSink,
    NoopAuditSink,
    get_audit_sink,
)


class TestAuditEvent:
    def test_to_json_roundtrip(self):
        ev = AuditEvent(
            event_type='authz_decision',
            decision='deny',
            principal='alice',
            roles=['opensearch-reader'],
            action='GenericOpenSearchApiTool',
            resource='Cluster::default',
            reason=[],
        )
        d = json.loads(ev.to_json())
        assert d['event_type'] == 'authz_decision'
        assert d['decision'] == 'deny'
        assert d['principal'] == 'alice'
        assert d['action'] == 'GenericOpenSearchApiTool'
        assert d['timestamp'].endswith('Z')  # auto-populated


class TestInterfaceEnforcement:
    def test_incomplete_subclass_cannot_instantiate(self):
        class Bad(AuditSink):
            pass

        with pytest.raises(TypeError):
            Bad()

    def test_sinks_are_subclasses(self):
        assert issubclass(NoopAuditSink, AuditSink)
        assert issubclass(LoggingAuditSink, AuditSink)
        assert issubclass(FileAuditSink, AuditSink)


class TestFileAuditSink:
    def test_writes_jsonl(self, tmp_path):
        path = tmp_path / 'audit.log'
        sink = FileAuditSink(str(path))
        sink.emit(AuditEvent(event_type='authz_decision', decision='allow', principal='u1'))
        sink.emit(AuditEvent(event_type='authz_decision', decision='deny', principal='u2'))
        sink.close()

        lines = path.read_text(encoding='utf-8').strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        assert first['principal'] == 'u1' and first['decision'] == 'allow'
        assert second['principal'] == 'u2' and second['decision'] == 'deny'

    def test_creates_parent_dir(self, tmp_path):
        path = tmp_path / 'nested' / 'dir' / 'audit.log'
        sink = FileAuditSink(str(path))
        sink.emit(AuditEvent(event_type='authn'))
        sink.close()
        assert path.exists()

    def test_emit_never_raises_after_close(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix='.log') as tf:
            sink = FileAuditSink(tf.name)
            sink.close()
            # writing after close must be swallowed, not raised
            sink.emit(AuditEvent(event_type='authz_decision'))


class TestNoopSink:
    def test_drops(self):
        NoopAuditSink().emit(AuditEvent(event_type='authz_decision'))  # no error, no output


class TestFactory:
    def test_disabled_returns_noop(self, monkeypatch):
        monkeypatch.delenv('AUDIT_ENABLED', raising=False)
        assert isinstance(get_audit_sink(), NoopAuditSink)

    def test_logging_sink(self, monkeypatch):
        monkeypatch.setenv('AUDIT_ENABLED', 'true')
        monkeypatch.setenv('AUDIT_SINK', 'logging')
        assert isinstance(get_audit_sink(), LoggingAuditSink)

    def test_file_sink(self, monkeypatch, tmp_path):
        monkeypatch.setenv('AUDIT_ENABLED', 'true')
        monkeypatch.setenv('AUDIT_SINK', 'file')
        monkeypatch.setenv('AUDIT_FILE_PATH', str(tmp_path / 'a.log'))
        sink = get_audit_sink()
        assert isinstance(sink, FileAuditSink)
        sink.close()

    def test_unknown_sink_raises(self, monkeypatch):
        monkeypatch.setenv('AUDIT_ENABLED', 'true')
        monkeypatch.setenv('AUDIT_SINK', 'kafka')
        with pytest.raises(ValueError):
            get_audit_sink()
