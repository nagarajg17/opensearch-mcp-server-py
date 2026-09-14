# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the authorization module."""

import pytest
from mcp_server_opensearch.authorization import (
    AuthorizationClient,
    AuthzRequest,
    AvpClient,
    CedarAgentClient,
    NoopAuthorizationClient,
    extract_roles,
    get_authorization_client,
)
from unittest.mock import patch


class TestExtractRoles:
    def test_filters_by_prefix(self):
        claims = {'realm_access': {'roles': ['opensearch-reader', 'admin', 'offline_access']}}
        assert extract_roles(claims) == ['opensearch-reader']

    def test_custom_prefix(self):
        claims = {'realm_access': {'roles': ['os:read', 'opensearch-writer']}}
        assert extract_roles(claims, role_prefix='os:') == ['os:read']

    def test_none_and_empty(self):
        assert extract_roles(None) == []
        assert extract_roles({}) == []
        assert extract_roles({'realm_access': {}}) == []


class TestInterfaceEnforcement:
    def test_incomplete_subclass_cannot_instantiate(self):
        class Bad(AuthorizationClient):
            pass

        with pytest.raises(TypeError):
            Bad()

    def test_concrete_clients_are_subclasses(self):
        assert issubclass(NoopAuthorizationClient, AuthorizationClient)
        assert issubclass(CedarAgentClient, AuthorizationClient)
        assert issubclass(AvpClient, AuthorizationClient)


class TestNoopClient:
    async def test_allows_everything(self):
        client = NoopAuthorizationClient()
        decision = await client.is_authorized(
            AuthzRequest(principal_id='u', roles=[], action='SearchIndexTool',
                         resource_type='Index', resource_id='x')
        )
        assert decision.allowed is True


class TestFactory:
    def test_disabled_returns_noop(self, monkeypatch):
        monkeypatch.delenv('AUTHZ_ENABLED', raising=False)
        assert isinstance(get_authorization_client(), NoopAuthorizationClient)

    def test_cedar_agent_backend(self, monkeypatch):
        monkeypatch.setenv('AUTHZ_ENABLED', 'true')
        monkeypatch.setenv('AUTHZ_BACKEND', 'cedar-agent')
        assert isinstance(get_authorization_client(), CedarAgentClient)

    def test_avp_backend(self, monkeypatch):
        monkeypatch.setenv('AUTHZ_ENABLED', 'true')
        monkeypatch.setenv('AUTHZ_BACKEND', 'avp')
        assert isinstance(get_authorization_client(), AvpClient)

    def test_unknown_backend_raises(self, monkeypatch):
        monkeypatch.setenv('AUTHZ_ENABLED', 'true')
        monkeypatch.setenv('AUTHZ_BACKEND', 'nope')
        with pytest.raises(ValueError):
            get_authorization_client()


class _FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._payload

    async def text(self):
        return str(self._payload)


class _FakeSession:
    def __init__(self, response, captured):
        self._response = response
        self._captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def post(self, url, json=None, headers=None):
        self._captured['url'] = url
        self._captured['body'] = json
        return self._response


class TestCedarAgentClient:
    async def test_allow_decision_and_request_shape(self):
        captured = {}
        resp = _FakeResponse(200, {'decision': 'Allow', 'diagnostics': {'reason': ['reader-policy']}})

        import aiohttp

        with patch.object(aiohttp, 'ClientSession', lambda *a, **k: _FakeSession(resp, captured)):
            client = CedarAgentClient(base_url='http://cedar:8180')
            decision = await client.is_authorized(
                AuthzRequest(principal_id='alice', roles=['opensearch-reader'],
                             action='SearchIndexTool', resource_type='Index', resource_id='books')
            )

        assert decision.allowed is True
        assert decision.reason == ['reader-policy']
        # request is namespaced and carries inline role hierarchy + user
        body = captured['body']
        assert body['principal'] == 'OpensearchMCP::User::"alice"'
        assert body['action'] == 'OpensearchMCP::Action::"SearchIndexTool"'
        assert body['resource'] == 'OpensearchMCP::Index::"books"'
        types = {e['uid']['type'] for e in body['entities']}
        assert 'OpensearchMCP::Role' in types and 'OpensearchMCP::User' in types
        user = [e for e in body['entities'] if e['uid']['type'] == 'OpensearchMCP::User'][0]
        assert user['parents'] == [{'type': 'OpensearchMCP::Role', 'id': 'opensearch-reader'}]

    async def test_deny_decision(self):
        captured = {}
        resp = _FakeResponse(200, {'decision': 'Deny', 'diagnostics': {'reason': []}})
        import aiohttp

        with patch.object(aiohttp, 'ClientSession', lambda *a, **k: _FakeSession(resp, captured)):
            client = CedarAgentClient()
            decision = await client.is_authorized(
                AuthzRequest(principal_id='u', roles=['opensearch-reader'],
                             action='GenericOpenSearchApiTool', resource_type='Cluster', resource_id='default')
            )
        assert decision.allowed is False

    async def test_fail_closed_on_error(self):
        resp = _FakeResponse(500, 'boom')
        import aiohttp

        with patch.object(aiohttp, 'ClientSession', lambda *a, **k: _FakeSession(resp, {})):
            client = CedarAgentClient(fail_open=False)
            decision = await client.is_authorized(
                AuthzRequest(principal_id='u', roles=[], action='SearchIndexTool',
                             resource_type='Index', resource_id='x')
            )
        assert decision.allowed is False

    async def test_fail_open_on_error(self):
        resp = _FakeResponse(500, 'boom')
        import aiohttp

        with patch.object(aiohttp, 'ClientSession', lambda *a, **k: _FakeSession(resp, {})):
            client = CedarAgentClient(fail_open=True)
            decision = await client.is_authorized(
                AuthzRequest(principal_id='u', roles=[], action='SearchIndexTool',
                             resource_type='Index', resource_id='x')
            )
        assert decision.allowed is True


class TestAvpClient:
    async def test_not_implemented(self):
        with pytest.raises(NotImplementedError):
            await AvpClient().is_authorized(
                AuthzRequest(principal_id='u', roles=[], action='SearchIndexTool',
                             resource_type='Index', resource_id='x')
            )
