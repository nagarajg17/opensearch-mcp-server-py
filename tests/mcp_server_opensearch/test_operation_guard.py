# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for operation_guard: destructive classification (A) and query guards (B)."""

from mcp_server_opensearch.operation_guard import (
    check_query_guards,
    classify_operation,
    is_destructive,
)


class TestClassifyOperation:
    def test_read_methods(self):
        assert classify_operation('GenericOpenSearchApiTool', {'method': 'GET', 'path': '/_cat/indices'}) == 'read'
        assert classify_operation('GenericOpenSearchApiTool', {'method': 'HEAD', 'path': '/my-index'}) == 'read'

    def test_non_destructive_write(self):
        assert classify_operation('GenericOpenSearchApiTool', {'method': 'POST', 'path': '/my-index/_doc'}) == 'write'
        assert classify_operation('GenericOpenSearchApiTool', {'method': 'PUT', 'path': '/my-index/_mapping'}) == 'write'

    def test_destructive_delete_method(self):
        assert is_destructive('GenericOpenSearchApiTool', {'method': 'DELETE', 'path': '/my-index'})
        assert is_destructive('GenericOpenSearchApiTool', {'method': 'DELETE', 'path': '/my-index/_doc/1'})
        assert is_destructive('GenericOpenSearchApiTool', {'method': 'DELETE', 'path': '/_all'})

    def test_destructive_paths(self):
        for method, path in [
            ('POST', '/my-index/_delete_by_query'),
            ('POST', '/my-index/_close'),
            ('POST', '/_reindex'),
            ('PUT', '/_cluster/settings'),
            ('PUT', '/_scripts/my-script'),
            ('DELETE', '/_scripts/my-script'),
        ]:
            assert is_destructive('GenericOpenSearchApiTool', {'method': method, 'path': path}), (method, path)

    def test_get_scripts_is_read(self):
        # reading a stored script is not destructive
        assert not is_destructive('GenericOpenSearchApiTool', {'method': 'GET', 'path': '/_scripts/my-script'})

    def test_non_generic_tools_are_read(self):
        assert classify_operation('SearchIndexTool', {'index': 'x'}) == 'read'
        assert not is_destructive('SearchIndexTool', {'index': 'x'})

    def test_defaults_when_missing(self):
        # method defaults to GET
        assert classify_operation('GenericOpenSearchApiTool', {'path': '/_search'}) == 'read'


class TestQueryGuards:
    def test_allows_normal(self):
        assert check_query_guards('SearchIndexTool', {'index': 'x', 'query_dsl': {'query': {'match_all': {}}}}) is None

    def test_blocks_inline_script(self, monkeypatch):
        monkeypatch.delenv('OPENSEARCH_ALLOW_SCRIPTING', raising=False)
        body = {'query': {'bool': {'filter': {'script': {'script': "doc['x'].value > 1"}}}}}
        msg = check_query_guards('GenericOpenSearchApiTool', {'method': 'POST', 'path': '/x/_search', 'body': body})
        assert msg is not None and 'scripting' in msg.lower()

    def test_allows_script_when_enabled(self, monkeypatch):
        monkeypatch.setenv('OPENSEARCH_ALLOW_SCRIPTING', 'true')
        body = {'query': {'script': {'script': 'x'}}}
        assert check_query_guards('GenericOpenSearchApiTool', {'body': body}) is None

    def test_blocks_oversized(self, monkeypatch):
        monkeypatch.setenv('OPENSEARCH_MAX_RESULT_SIZE', '100')
        msg = check_query_guards('SearchIndexTool', {'index': 'x', 'size': 5000})
        assert msg is not None and '5000' in msg

    def test_size_within_limit_ok(self, monkeypatch):
        monkeypatch.setenv('OPENSEARCH_MAX_RESULT_SIZE', '1000')
        assert check_query_guards('SearchIndexTool', {'index': 'x', 'size': 50}) is None

    def test_size_in_body(self, monkeypatch):
        monkeypatch.setenv('OPENSEARCH_MAX_RESULT_SIZE', '100')
        body = {'query': {'match_all': {}}, 'size': 999}
        msg = check_query_guards('GenericOpenSearchApiTool', {'method': 'POST', 'path': '/x/_search', 'body': body})
        assert msg is not None
