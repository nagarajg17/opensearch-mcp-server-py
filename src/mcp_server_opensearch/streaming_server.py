# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import contextlib
import logging
import uuid
import uvicorn
from mcp.server import Server
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, TextContent, Tool
from mcp_server_opensearch.audit import AuditEvent, AuditSink, get_audit_sink
from mcp_server_opensearch.authorization import (
    AuthzRequest,
    extract_roles,
    get_authorization_client,
)
from mcp_server_opensearch.client_context import ClientNameMiddleware, client_name_var
from mcp_server_opensearch.clusters_information import load_clusters_from_yaml
from mcp_server_opensearch.global_state import set_config_file_path, set_mode, set_profile
from mcp_server_opensearch.oauth import JwtTokenVerifier, OAuthConfig, load_oauth_config
from mcp_server_opensearch.operation_guard import check_query_guards, is_destructive
from mcp_server_opensearch.server_instructions import get_server_instructions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
from tools.config import apply_custom_tool_config
from tools.tool_filter import get_tools
from tools.tool_generator import generate_tools_from_openapi
from tools.tools import TOOL_REGISTRY
from typing import AsyncIterator


def _resource_for(params: CallToolRequestParams) -> tuple[str, str]:
    """Map a tool call to a Cedar resource (type, id).

    Tools that target an index map to ``Index::<name>``; everything else maps to
    ``Cluster::default``. Kept intentionally simple; refine per-tool as needed.
    """
    args = params.arguments or {}
    index = args.get('index')
    if isinstance(index, str) and index.strip():
        return 'Index', index.strip()
    if isinstance(index, list) and index:
        return 'Index', str(index[0])
    return 'Cluster', 'default'


async def create_mcp_server(
    mode: str = 'single',
    profile: str = '',
    config_file_path: str = '',
    cli_tool_overrides: dict | None = None,
    audit_sink: AuditSink | None = None,
) -> Server:
    """Create and configure the MCP server instance."""
    # Set the global mode
    set_mode(mode)

    # Set the global profile if provided
    if profile:
        set_profile(profile)

    # Set the global config file path
    if config_file_path:
        set_config_file_path(config_file_path)

    # Load clusters from YAML file
    if mode == 'multi':
        await load_clusters_from_yaml(config_file_path)

    # Call tool generator
    await generate_tools_from_openapi()
    # Apply custom tool config (custom name and description)
    customized_registry = apply_custom_tool_config(
        TOOL_REGISTRY, config_file_path, cli_tool_overrides or {}
    )
    # Get enabled tools (tool filter)
    enabled_tools = await get_tools(
        tool_registry=customized_registry, config_file_path=config_file_path
    )
    logging.info(f'Enabled tools: {list(enabled_tools.keys())}')

    # Policy Decision Point (PDP) — cedar-agent / AVP / noop, selected by env.
    authz_client = get_authorization_client()
    # Security audit sink — file / logging / noop, selected by env.
    # Reuse a passed-in sink (so serve() can close it on shutdown) or build one.
    if audit_sink is None:
        audit_sink = get_audit_sink()

    async def _list_tools(ctx, params) -> ListToolsResult:
        tools = []
        for tool_name, tool_info in enabled_tools.items():
            tools.append(
                Tool(
                    name=tool_info.get('display_name', tool_name),
                    description=tool_info['description'],
                    input_schema=tool_info['input_schema'],
                    meta={'category': tool_info['category']}
                    if tool_info.get('category')
                    else None,  # type: ignore[call-arg]
                )
            )
        return ListToolsResult(tools=tools)

    async def _call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
        from mcp_server_opensearch.client_context import request_context_var
        from mcp_server_opensearch.tool_executor import _build_call_tool_result, execute_tool

        # --- Authorization (PEP): check before executing the tool ---
        access = get_access_token()
        claims = getattr(access, 'claims', None) if access else None
        principal_id = (
            (access.subject if access and access.subject else None)
            or (claims or {}).get('preferred_username')
            or 'anonymous'
        )
        roles = extract_roles(claims)
        res_type, res_id = _resource_for(params)

        # Destructive GenericOpenSearchApiTool calls (delete, delete-by-query, close,
        # reindex, cluster settings, stored scripts) route to a dedicated Cedar action
        # that only admins may perform — containing a manipulated agent's blast radius.
        authz_action = params.name
        if params.name == 'GenericOpenSearchApiTool' and is_destructive(params.name, params.arguments):
            authz_action = 'DestructiveOperation'

        decision = await authz_client.is_authorized(
            AuthzRequest(
                principal_id=str(principal_id),
                roles=roles,
                action=authz_action,
                resource_type=res_type,
                resource_id=res_id,
                context={'scopes': list(access.scopes) if access else []},
            )
        )

        # --- Security audit: record the authorization decision (allow AND deny) ---
        audit_sink.emit(
            AuditEvent(
                event_type='authz_decision',
                decision='allow' if decision.allowed else 'deny',
                principal=str(principal_id),
                client_id=(access.client_id if access else None),
                roles=roles,
                scopes=list(access.scopes) if access else [],
                action=authz_action,
                resource=f'{res_type}::{res_id}',
                reason=decision.reason,
                request_id=uuid.uuid4().hex,
                client_name=client_name_var.get('unknown'),
                extra={'tool': params.name},
            )
        )

        if not decision.allowed:
            logging.info(
                'AuthZ DENY principal=%s roles=%s action=%s resource=%s::%s reason=%s',
                principal_id,
                roles,
                authz_action,
                res_type,
                res_id,
                decision.reason,
            )
            return _build_call_tool_result(
                [
                    TextContent(
                        type='text',
                        text=(
                            f"Authorization denied: principal '{principal_id}' with roles "
                            f'{roles or "[]"} is not permitted to call {authz_action} on '
                            f'{res_type}::{res_id}.'
                        ),
                    )
                ],
                is_error=True,
            )

        # --- Query guards (B): reject abusive query shapes even when authorized ---
        guard_error = check_query_guards(params.name, params.arguments)
        if guard_error:
            logging.info(
                'Query guard blocked principal=%s action=%s: %s',
                principal_id,
                params.name,
                guard_error,
            )
            audit_sink.emit(
                AuditEvent(
                    event_type='query_guard_block',
                    decision='deny',
                    principal=str(principal_id),
                    roles=roles,
                    action=params.name,
                    resource=f'{res_type}::{res_id}',
                    reason=[guard_error],
                    request_id=uuid.uuid4().hex,
                    client_name=client_name_var.get('unknown'),
                )
            )
            return _build_call_tool_result(
                [TextContent(type='text', text=f'Request blocked: {guard_error}')],
                is_error=True,
            )

        token = request_context_var.set(ctx.request)
        try:
            return await execute_tool(params.name, params.arguments or {}, enabled_tools)
        except MCPError:
            raise
        except Exception as e:
            return _build_call_tool_result(
                [
                    TextContent(
                        type='text',
                        text=str(e),
                    )
                ],
                is_error=True,
            )
        finally:
            request_context_var.reset(token)

    # Server instructions guide the LLM on dynamic connection params (single mode only)
    server = Server(
        'opensearch-mcp-server',
        instructions=get_server_instructions(),
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )

    return server


class _ASGIApp:
    """ASGI app object wrapping a handler, so Starlette's Route treats it as a raw ASGI endpoint."""

    def __init__(self, handler):
        self._handler = handler

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._handler(scope, receive, send)


class MCPStarletteApp:
    """Starlette application wrapper for the MCP server."""

    def __init__(
        self,
        mcp_server: Server,
        stateless: bool = True,
        oauth_config: OAuthConfig | None = None,
        audit_sink: AuditSink | None = None,
    ):
        """Initialize the MCP Starlette application."""
        self.mcp_server = mcp_server
        self.oauth_config = oauth_config
        self.audit_sink = audit_sink
        self.sse = SseServerTransport('/messages/')
        self.session_manager = StreamableHTTPSessionManager(
            app=self.mcp_server,
            event_store=None,
            json_response=False,
            stateless=stateless,
        )

    async def handle_sse(self, request: Request) -> Response:
        """Handle SSE connection requests."""
        async with self.sse.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await self.mcp_server.run(
                read_stream,
                write_stream,
                self.mcp_server.create_initialization_options(),
            )

        # Done to prevent 'NoneType' errors. For more details: https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/sse.py#L33-L37
        return Response()

    async def handle_health(self, request: Request) -> Response:
        """Handle health check requests."""
        return Response('OK', status_code=200)

    @contextlib.asynccontextmanager
    async def lifespan(self, app: Starlette) -> AsyncIterator[None]:
        """Context manager for session manager lifecycle.

        Ensures proper startup and shutdown of the session manager.
        """
        from mcp_server_opensearch.logging_config import start_memory_monitor

        async with self.session_manager.run():
            logging.info('Application started with StreamableHTTP session manager!')
            monitor_task = start_memory_monitor()
            try:
                yield
            finally:
                monitor_task.cancel()
                try:
                    await monitor_task
                except (asyncio.CancelledError, Exception):
                    pass
                if self.audit_sink is not None:
                    self.audit_sink.close()
                logging.info('Application shutting down...')

    async def handle_streamable_http(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Handle streamable HTTP requests."""
        await self.session_manager.handle_request(scope, receive, send)

    def create_app(self) -> Starlette:
        """Create the Starlette application with routes."""
        # Serve bare '/mcp' via Route (a Mount alone 307-redirects '/mcp' to '/mcp/'); Mount handles sub-paths.
        streamable_http_app = _ASGIApp(self.handle_streamable_http)

        # ClientNameMiddleware is always active for per-client attribution in logs.
        middleware: list[Middleware] = [Middleware(ClientNameMiddleware)]
        routes: list[Route | Mount] = []

        if self.oauth_config and self.oauth_config.enabled:
            token_verifier = JwtTokenVerifier(self.oauth_config)
            middleware = [
                Middleware(ClientNameMiddleware),
                Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(token_verifier)),
                Middleware(AuthContextMiddleware),
            ]
            resource_url = AnyHttpUrl(self.oauth_config.resource_url)
            resource_metadata_url = build_resource_metadata_url(resource_url)
            required_scopes = self.oauth_config.required_scopes

            routes.extend(
                [
                    Route(
                        '/sse',
                        endpoint=RequireAuthMiddleware(
                            self.handle_sse,
                            required_scopes,
                            resource_metadata_url,
                        ),
                        methods=['GET'],
                    ),
                    Route('/health', endpoint=self.handle_health, methods=['GET']),
                    Mount(
                        '/messages/',
                        app=RequireAuthMiddleware(
                            self.sse.handle_post_message,
                            required_scopes,
                            resource_metadata_url,
                        ),
                    ),
                    Route(
                        '/mcp',
                        endpoint=RequireAuthMiddleware(
                            streamable_http_app,
                            required_scopes,
                            resource_metadata_url,
                        ),
                        methods=['GET', 'POST', 'DELETE'],
                    ),
                    Mount(
                        '/mcp',
                        app=RequireAuthMiddleware(
                            streamable_http_app,
                            required_scopes,
                            resource_metadata_url,
                        ),
                    ),
                ]
            )
            routes.extend(
                create_protected_resource_routes(
                    resource_url=resource_url,
                    authorization_servers=[AnyHttpUrl(self.oauth_config.issuer_url)],
                    scopes_supported=required_scopes,
                    resource_name='OpenSearch MCP Server',
                )
            )
        else:
            routes.extend(
                [
                    Route('/sse', endpoint=self.handle_sse, methods=['GET']),
                    Route('/health', endpoint=self.handle_health, methods=['GET']),
                    Mount('/messages/', app=self.sse.handle_post_message),
                    Route('/mcp', endpoint=streamable_http_app),
                    Mount('/mcp', app=streamable_http_app),
                ]
            )

        return Starlette(
            routes=routes,
            middleware=middleware,
            lifespan=self.lifespan,
        )


async def serve(
    host: str = '127.0.0.1',
    port: int = 9900,
    mode: str = 'single',
    profile: str = '',
    config_file_path: str = '',
    cli_tool_overrides: dict | None = None,
    stateless: bool = True,
) -> None:
    """Start the MCP server in streaming HTTP mode."""
    audit_sink = get_audit_sink()
    mcp_server = await create_mcp_server(
        mode, profile, config_file_path, cli_tool_overrides, audit_sink=audit_sink
    )
    oauth_config = load_oauth_config(host, port)
    app_handler = MCPStarletteApp(
        mcp_server, stateless=stateless, oauth_config=oauth_config, audit_sink=audit_sink
    )
    app = app_handler.create_app()

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        timeout_graceful_shutdown=10,
    )
    server = uvicorn.Server(config)
    await server.serve()
