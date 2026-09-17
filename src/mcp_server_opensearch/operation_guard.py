# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

"""Operation guards for hardening MCP tool calls against unsafe use.

Two independent, prompt-injection-focused controls:

A. **Destructive-operation classification** — the ``GenericOpenSearchApiTool`` can
   call any endpoint with any HTTP method, so a manipulated agent could delete
   indices, run delete-by-query, change cluster settings, etc. :func:`classify_operation`
   maps a call to ``read`` / ``write`` / ``destructive`` so the authorization layer can
   route destructive calls to a Cedar action that only admins may perform.

B. **Query guards** — :func:`check_query_guards` rejects abusive query shapes
   (inline scripting, oversized result windows) that could drive resource-exhaustion
   or code-execution style attacks.

Both are pure functions (env read lazily) so they are easy to unit-test.
"""

import os
from typing import Any


_READ_METHODS = {'GET', 'HEAD'}

# Substrings in an API path that make an operation destructive regardless of index.
_DESTRUCTIVE_PATH_SUBSTRINGS = (
    '/_delete_by_query',
    '/_close',
    '/_reindex',
)


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _is_destructive(method: str, path: str) -> bool:
    """Return True if a (method, path) is a destructive OpenSearch operation."""
    method = method.upper()
    path = path.lower()
    if method == 'DELETE':
        # delete index, delete document, delete alias, delete-by-id, DELETE /_all, ...
        return True
    if any(sub in path for sub in _DESTRUCTIVE_PATH_SUBSTRINGS):
        return True
    # Stored scripts are executable code — mutating them is destructive.
    if method in {'PUT', 'POST', 'DELETE'} and '/_scripts' in path:
        return True
    # Cluster-wide reconfiguration.
    if method == 'PUT' and '/_cluster/settings' in path:
        return True
    return False


def classify_operation(tool_name: str, arguments: dict[str, Any] | None) -> str:
    """Classify a tool call as 'read', 'write', or 'destructive'.

    Only ``GenericOpenSearchApiTool`` (arbitrary method+path) needs real
    classification; the specialized read tools are always 'read'.
    """
    args = arguments or {}
    if tool_name != 'GenericOpenSearchApiTool':
        return 'read'
    method = str(args.get('method') or 'GET').upper()
    path = str(args.get('path') or '')
    if _is_destructive(method, path):
        return 'destructive'
    if method in _READ_METHODS:
        return 'read'
    return 'write'


def is_destructive(tool_name: str, arguments: dict[str, Any] | None) -> bool:
    """Convenience: True if the call is a destructive operation."""
    return classify_operation(tool_name, arguments) == 'destructive'


def _contains_script(obj: Any) -> bool:
    """Recursively detect an inline ``script`` field in a query body."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == 'script':
                return True
            if _contains_script(v):
                return True
    elif isinstance(obj, list):
        return any(_contains_script(item) for item in obj)
    return False


def _extract_size(arguments: dict[str, Any], body: Any) -> int | None:
    """Best-effort extraction of a requested result-window size."""
    for candidate in (arguments.get('size'), (arguments.get('query_params') or {}).get('size')):
        if candidate is not None:
            try:
                return int(candidate)
            except (TypeError, ValueError):
                pass
    if isinstance(body, dict) and body.get('size') is not None:
        try:
            return int(body['size'])
        except (TypeError, ValueError):
            return None
    return None


def check_query_guards(tool_name: str, arguments: dict[str, Any] | None) -> str | None:
    """Return an error message if the call violates a query guard, else None.

    Guards (env-configurable):
    - Inline scripting rejected unless ``OPENSEARCH_ALLOW_SCRIPTING=true``.
    - Result window capped at ``OPENSEARCH_MAX_RESULT_SIZE`` (default 1000).
    """
    args = arguments or {}
    body = args.get('body')
    if body is None:
        body = args.get('query_dsl')

    if not _is_truthy(os.getenv('OPENSEARCH_ALLOW_SCRIPTING')) and _contains_script(body):
        return 'Inline scripting is disabled (set OPENSEARCH_ALLOW_SCRIPTING=true to allow).'

    try:
        max_size = int(os.getenv('OPENSEARCH_MAX_RESULT_SIZE', '1000'))
    except ValueError:
        max_size = 1000
    size = _extract_size(args, body)
    if size is not None and size > max_size:
        return f'Requested size {size} exceeds the maximum allowed ({max_size}).'

    return None
