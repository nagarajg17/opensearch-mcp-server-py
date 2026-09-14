# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Pluggable authorization (AuthZ) for MCP tool calls.

Authentication (who the caller is) is handled by ``oauth.py``. This module adds
*authorization* (what the caller may do): each tool call is checked against a
policy decision point (PDP) before execution.

Design
------
- ``AuthorizationClient`` is the port the server depends on. It is deliberately
  transport-agnostic: every backend (a local Cedar sidecar today, Amazon Verified
  Permissions later) is just an ``is_authorized`` API call behind this interface.
- ``CedarAgentClient`` talks to a ``cedar-agent`` sidecar over HTTP.
- ``AvpClient`` is a stub for Amazon Verified Permissions (same interface).
- ``NoopAuthorizationClient`` allows everything and is used when AuthZ is disabled,
  preserving the server's default (auth-only) behavior.

Selection is env-driven via :func:`get_authorization_client`.

Environment variables
---------------------
- ``AUTHZ_ENABLED``        : enable authorization (default: off -> allow all)
- ``AUTHZ_BACKEND``        : ``cedar-agent`` (default) or ``avp``
- ``CEDAR_AGENT_URL``      : cedar-agent base URL (default ``http://localhost:8180``)
- ``AUTHZ_ROLE_PREFIX``    : only token roles with this prefix are sent as the
                             principal's roles (default ``opensearch-``)
- ``AUTHZ_TIMEOUT``        : PDP request timeout in seconds (default ``5``)
- ``AUTHZ_FAIL_OPEN``      : if ``true``, allow when the PDP errors (default: off ->
                             fail closed / deny on PDP error)
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {'1', 'true', 'yes', 'on'}


@dataclass
class AuthzDecision:
    """Result of an authorization check."""

    allowed: bool
    reason: list[str] = field(default_factory=list)


@dataclass
class AuthzRequest:
    """A single authorization question: may <principal> do <action> on <resource>?"""

    principal_id: str
    roles: list[str]
    action: str
    resource_type: str
    resource_id: str
    context: dict[str, Any] = field(default_factory=dict)


class AuthorizationClient(ABC):
    """Interface (port) for a policy decision point (PDP).

    Concrete backends MUST inherit this class and implement ``is_authorized``.
    Enforced like a Java interface: instantiating a subclass that does not
    implement the abstract method raises ``TypeError``.
    """

    @abstractmethod
    async def is_authorized(self, request: AuthzRequest) -> AuthzDecision:
        """Return an allow/deny decision for the given request."""
        raise NotImplementedError


class NoopAuthorizationClient(AuthorizationClient):
    """Allow-all PDP used when authorization is disabled."""

    async def is_authorized(self, request: AuthzRequest) -> AuthzDecision:
        """Always allow."""
        return AuthzDecision(allowed=True, reason=['authz-disabled'])


# Cedar namespace that all entity types and actions live under. Must match the
# namespace key in cedar/schema.json and the qualifiers in cedar/policies.json.
CEDAR_NAMESPACE = os.getenv('CEDAR_NAMESPACE', 'OpensearchMCP')
_ROLE_TYPE = f'{CEDAR_NAMESPACE}::Role'
_USER_TYPE = f'{CEDAR_NAMESPACE}::User'


# Authoritative role hierarchy, shipped inline with every Cedar query. This is the
# single source of truth: the cedar-agent data store is left empty, and hierarchy is
# NOT modeled in the identity provider (Keycloak emits flat role assignments). Kept in
# Cedar's domain so it extends alongside policies. cedar-agent replaces (does not merge)
# the entity store when inline entities are supplied, so the principal's role ancestry
# must travel with each request for inheritance to work. admin -> writer -> reader.
_ROLE_HIERARCHY: list[dict[str, Any]] = [
    {'uid': {'type': _ROLE_TYPE, 'id': 'opensearch-reader'}, 'attrs': {}, 'parents': []},
    {
        'uid': {'type': _ROLE_TYPE, 'id': 'opensearch-writer'},
        'attrs': {},
        'parents': [{'type': _ROLE_TYPE, 'id': 'opensearch-reader'}],
    },
    {
        'uid': {'type': _ROLE_TYPE, 'id': 'opensearch-admin'},
        'attrs': {},
        'parents': [{'type': _ROLE_TYPE, 'id': 'opensearch-writer'}],
    },
]


class CedarAgentClient(AuthorizationClient):
    """AuthorizationClient backed by a cedar-agent sidecar (HTTP)."""

    def __init__(
        self,
        base_url: str = 'http://localhost:8180',
        timeout: float = 5.0,
        fail_open: bool = False,
        auth_token: str | None = None,
        role_entities: list[dict[str, Any]] | None = None,
    ):
        """Configure the cedar-agent client."""
        self._url = base_url.rstrip('/') + '/v1/is_authorized'
        self._timeout = timeout
        self._fail_open = fail_open
        self._headers = {'Content-Type': 'application/json'}
        if auth_token:
            self._headers['Authorization'] = f'Bearer {auth_token}'
        # Role ancestry to ship inline with each request.
        self._role_entities = role_entities if role_entities is not None else _ROLE_HIERARCHY

    async def is_authorized(self, request: AuthzRequest) -> AuthzDecision:
        """Query cedar-agent's /v1/is_authorized endpoint."""
        import aiohttp

        principal = f'{CEDAR_NAMESPACE}::User::"{request.principal_id}"'
        action = f'{CEDAR_NAMESPACE}::Action::"{request.action}"'
        resource = f'{CEDAR_NAMESPACE}::{request.resource_type}::"{request.resource_id}"'

        # Inline entities = static role hierarchy + this user's role memberships.
        user_entity = {
            'uid': {'type': _USER_TYPE, 'id': request.principal_id},
            'attrs': {},
            'parents': [{'type': _ROLE_TYPE, 'id': r} for r in request.roles],
        }
        body = {
            'principal': principal,
            'action': action,
            'resource': resource,
            'context': request.context or {},
            'entities': [*self._role_entities, user_entity],
        }

        try:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self._url, json=body, headers=self._headers) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        logger.error(
                            'cedar-agent returned HTTP %s: %s', resp.status, text[:300]
                        )
                        return self._on_error(f'PDP HTTP {resp.status}')
                    data = await resp.json()
        except Exception as e:  # network error, timeout, bad JSON
            logger.error('cedar-agent authorization call failed: %s', e)
            return self._on_error(f'PDP unreachable: {e}')

        decision = str(data.get('decision', '')).lower() == 'allow'
        reason = data.get('diagnostics', {}).get('reason', [])
        return AuthzDecision(allowed=decision, reason=reason)

    def _on_error(self, why: str) -> AuthzDecision:
        if self._fail_open:
            logger.warning('AuthZ failing OPEN due to: %s', why)
            return AuthzDecision(allowed=True, reason=[f'fail-open:{why}'])
        return AuthzDecision(allowed=False, reason=[f'fail-closed:{why}'])


class AvpClient(AuthorizationClient):
    """Stub AuthorizationClient for Amazon Verified Permissions.

    Kept as a same-interface placeholder so the server can switch PDPs by config
    without code changes. Implement using boto3 ``verifiedpermissions.is_authorized``.
    """

    def __init__(self, policy_store_id: str | None = None, **_: Any):
        """Record the target policy store; real wiring is TODO."""
        self._policy_store_id = policy_store_id

    async def is_authorized(self, request: AuthzRequest) -> AuthzDecision:
        """Not implemented yet."""
        raise NotImplementedError(
            'AVP authorization backend is not implemented yet. '
            'Use AUTHZ_BACKEND=cedar-agent.'
        )


def get_authorization_client() -> AuthorizationClient:
    """Build the configured AuthorizationClient from environment variables."""
    if not _is_truthy(os.getenv('AUTHZ_ENABLED')):
        logger.info('Authorization disabled (AUTHZ_ENABLED not set) -> allow all')
        return NoopAuthorizationClient()

    backend = os.getenv('AUTHZ_BACKEND', 'cedar-agent').strip().lower()
    timeout = float(os.getenv('AUTHZ_TIMEOUT', '5'))
    fail_open = _is_truthy(os.getenv('AUTHZ_FAIL_OPEN'))

    if backend == 'cedar-agent':
        url = os.getenv('CEDAR_AGENT_URL', 'http://localhost:8180')
        logger.info('Authorization enabled: cedar-agent at %s (fail_open=%s)', url, fail_open)
        return CedarAgentClient(
            base_url=url,
            timeout=timeout,
            fail_open=fail_open,
            auth_token=os.getenv('CEDAR_AGENT_AUTH_TOKEN') or None,
        )
    if backend == 'avp':
        logger.info('Authorization enabled: AVP (stub)')
        return AvpClient(policy_store_id=os.getenv('AVP_POLICY_STORE_ID'))

    raise ValueError(f'Unknown AUTHZ_BACKEND: {backend!r} (expected cedar-agent or avp)')


def extract_roles(claims: dict[str, Any] | None, role_prefix: str | None = None) -> list[str]:
    """Extract the caller's roles from token claims (Keycloak ``realm_access.roles``).

    Only roles matching ``role_prefix`` (default from ``AUTHZ_ROLE_PREFIX`` or
    ``opensearch-``) are returned, so unrelated realm roles are ignored.
    """
    if not claims:
        return []
    prefix = role_prefix if role_prefix is not None else os.getenv('AUTHZ_ROLE_PREFIX', 'opensearch-')
    realm_roles = (claims.get('realm_access') or {}).get('roles') or []
    return [r for r in realm_roles if isinstance(r, str) and r.startswith(prefix)]
