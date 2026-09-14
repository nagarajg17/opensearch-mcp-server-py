# Cedar Authorization for the OpenSearch MCP Server

Fine-grained **authorization (AuthZ)** for MCP tool calls, layered on top of the
OAuth **authentication (AuthN)** already provided by the streaming transport.

- **AuthN** (who are you?) — handled by `oauth.py`: the bearer token is verified
  against the OIDC provider (Keycloak, Cognito, AVP-backed IdP, …).
- **AuthZ** (what may you do?) — handled here: every tool call is checked against
  Cedar policies before it executes.

The two are independent: a valid token gets you *in*; Cedar decides *what you can call*.

## Architecture

```
MCP client --Bearer token--> MCP server ------------> OpenSearch
                              (PEP: _call_tool)
                                    |
                                    | is_authorized(principal, action, resource)
                                    v
                             AuthorizationClient          <-- interface (ABC)
                              |                \
                     CedarAgentClient        AvpClient      <-- implementations
                              |
                        HTTP /v1/is_authorized
                              v
                         cedar-agent  (embeds the Cedar engine)  <-- sidecar (PDP)
```

- **PEP (Policy Enforcement Point):** `_call_tool` in `streaming_server.py`. It maps
  the request to `(principal, action, resource)` and asks the PDP; a `Deny` returns an
  error before the tool runs.
- **PDP (Policy Decision Point):** a pluggable `AuthorizationClient`. Today
  `CedarAgentClient` talks to a [`cedar-agent`](https://github.com/permitio/cedar-agent)
  sidecar (which embeds the real Cedar engine). `AvpClient` is a stub for Amazon
  Verified Permissions — the same interface, so switching PDPs is a config change, not
  a code change. Both evaluate the *same* Cedar policies.

## Model

- **Namespace:** everything lives under `OpensearchMCP` (`OpensearchMCP::User`,
  `OpensearchMCP::Role`, `OpensearchMCP::Action`, `OpensearchMCP::Index`,
  `OpensearchMCP::Cluster`).
- **Actions:** one Cedar action per MCP tool (e.g. `OpensearchMCP::Action::"SearchIndexTool"`).
- **Resources:** a tool that targets an index maps to `Index::<name>`; everything else to
  `Cluster::default`.
- **Roles / tiers (`reader ⊂ writer ⊂ admin`):**
  - `opensearch-reader` — the read tools (search, list, mapping, count, health, …)
  - `opensearch-writer` — inherits reader + `GenericOpenSearchApiTool`
  - `opensearch-admin`  — inherits writer + everything (catch-all)

Roles come from the token (`realm_access.roles`, filtered by the `opensearch-` prefix).
The **role hierarchy lives only in Cedar** (`_ROLE_HIERARCHY` in `authorization.py`),
not in the identity provider — Keycloak emits flat role assignments, so the model
extends cleanly as new capability tiers are added.

## Files

| File | Purpose |
|------|---------|
| `schema.json` | Cedar schema: entity types + one action per tool, under the `OpensearchMCP` namespace |
| `policies.json` | The 3 policies: `reader-policy`, `writer-policy`, `admin-policy` |
| `load.sh` | Loads **schema + policies** into a running cedar-agent (data store left empty) |

## Configuration (environment variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHZ_ENABLED` | *(off)* | Enable authorization. When unset, all calls are allowed (auth-only behavior). |
| `AUTHZ_BACKEND` | `cedar-agent` | PDP backend: `cedar-agent` or `avp`. |
| `CEDAR_AGENT_URL` | `http://localhost:8180` | cedar-agent base URL. |
| `CEDAR_AGENT_AUTH_TOKEN` | *(none)* | Optional bearer token to authenticate to cedar-agent. |
| `AUTHZ_ROLE_PREFIX` | `opensearch-` | Only token roles with this prefix are used. |
| `AUTHZ_TIMEOUT` | `5` | PDP request timeout (seconds). |
| `AUTHZ_FAIL_OPEN` | *(off)* | If `true`, allow when the PDP errors. Default is **fail-closed** (deny on PDP error). |
| `CEDAR_NAMESPACE` | `OpensearchMCP` | Cedar namespace; must match `schema.json` / `policies.json`. |

## Running it

1. **Start the sidecar:**
   ```bash
   docker run -d --name cedar-agent -p 8180:8180 permitio/cedar-agent
   ```
2. **Load schema + policies:**
   ```bash
   ./cedar/load.sh                 # or: ./cedar/load.sh http://localhost:8180
   ```
3. **Start the MCP server with AuthZ enabled** (streaming transport, OAuth on):
   ```bash
   AUTHZ_ENABLED=true \
   AUTHZ_BACKEND=cedar-agent \
   CEDAR_AGENT_URL=http://localhost:8180 \
   MCP_OAUTH_ENABLED=true ... \
   python -m mcp_server_opensearch --transport stream --host 127.0.0.1 --port 9900
   ```

## How a request is authorized

For each tool call the PEP builds and sends:

```json
{
  "principal": "OpensearchMCP::User::\"<sub>\"",
  "action":    "OpensearchMCP::Action::\"SearchIndexTool\"",
  "resource":  "OpensearchMCP::Index::\"my-index\"",
  "context":   { "scopes": ["openid", "profile", "email"] },
  "entities":  [ /* role hierarchy */, { "uid": {"type":"OpensearchMCP::User","id":"<sub>"},
                                         "parents": [{"type":"OpensearchMCP::Role","id":"opensearch-writer"}] } ]
}
```

cedar-agent returns `{"decision":"Allow"|"Deny","diagnostics":{"reason":[...]}}`. On
`Deny` the tool is not executed and an authorization error is returned to the client.

## Testing

Unit tests: `tests/mcp_server_opensearch/test_authorization.py` (mocked PDP — no running
cedar-agent required). Run:

```bash
python -m pytest tests/mcp_server_opensearch/test_authorization.py -q
```
