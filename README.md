# agent-delegated-auth

A small, runnable reference for one question: **when an AI agent acts on behalf of a user, how do you make sure it can never do more than that user could?**

The agent here is an MCP server exposing finance tools (list budgets, approve budget requests). It holds no standing access to the finance API. For every tool call it trades the user's token, plus its own credential, for a short-lived token that carries the user's identity and permissions and names the agent as the actor. That trade uses OAuth 2.0 Token Exchange (RFC 8693). The finance API enforces RBAC and ABAC on that token and records both the user and the agent in an audit log.

Everything runs in-process (a mini authorization server, the finance API, the MCP server). No external IdP or network is needed.

## The problem

An agent that calls APIs with its own service account is a confused deputy waiting to happen. Its permissions are the union of everything any user might need, so any user who can steer it (or any prompt injection that reaches it) gets that union. The fix is to make the agent's effective permissions the **intersection** of what the user holds and what the agent is allowed to do, and to enforce that where the data lives, not in the agent.

## How a call flows

```
 User        MCP client         MCP server (agent)          IdP (authorization server)        Finance API
  |  sign in     |                      |                              |                                |
  |------------->|  user token          |                              |                                |
  |              |  aud=mcp server      |                              |                                |
  |              |--- tools/call ------>|                              |                                |
  |              |  (Authorization hdr  |-- client_credentials ------->|                                |
  |              |   or USER_TOKEN)     |<-- actor token (aud=IdP) ----|                                |
  |              |                      |-- token exchange (RFC 8693) >|                                |
  |              |                      |   subject_token = user token |  verify both tokens            |
  |              |                      |   actor_token   = agent      |  aud: allowed downstream?      |
  |              |                      |   audience = finance API     |  scope = req ∩ user ∩ agent    |
  |              |                      |   scope = budgets:approve    |                                |
  |              |                      |<-- token: sub=user,          |                                |
  |              |                      |    act={sub:agent}, aud=API, |                                |
  |              |                      |    roles/cost_centers of user|                                |
  |              |                      |    exp <= 5 min              |                                |
  |              |                      |-- POST /requests/R-201/approve (Bearer exchanged token) ----->|
  |              |                      |                              |   verify sig (JWKS), iss, aud, |
  |              |                      |                              |   exp; RBAC role+scope; ABAC   |
  |              |                      |                              |   cost center; audit user+act  |
  |              |<-- result / isError -|<--------------------------------------------- 200 / 403 ---|
```

## Why each mechanism

| Mechanism | What it prevents |
| --- | --- |
| **Token exchange (RFC 8693)** | The agent never holds long-lived API credentials. Every downstream token is minted for a specific user, from that user's live token. |
| **`act` (actor) claim** | `sub` stays the user, so authorization is the user's. `act.sub` records which agent acted. Delegation through a second agent nests: `act: { sub: sub-agent, act: { sub: finance-agent } }`. |
| **Audience restriction** (`aud`, RFC 7519; same intent as RFC 8707 resource indicators) | The user's token is addressed to the MCP server and is useless if replayed at the API. The exchanged token is addressed to exactly one API. The agent's own client token is addressed to the IdP, so on its own it opens nothing. |
| **Scope down-scoping** | Exchanged scope = requested ∩ user token scope ∩ agent's allowed scopes. The agent asks only for what the current call needs (`budgets:read` for reads, `budgets:approve` for approvals). An exchange can never add a scope. |
| **Attributes from the user, never the agent** | `roles` and `cost_centers` are copied from the subject token. The agent has no roles. |
| **RBAC + ABAC at the resource server** | The API, not the agent, decides. RBAC needs both the scope and a matching role (`viewer`/`approver`). ABAC limits every read and write to the user's `cost_centers`. A buggy or manipulated agent cannot argue its way past this. |
| **Audit with user + actor** | Every allowed or denied call is logged with `user` and the full actor chain, so "who did this" always has two answers: on whose behalf, and by which agent. |
| **Short lifetime** | Exchanged tokens live at most 5 minutes and never outlive the user's token. |

## Layout

```
src/
  idp/authServer.ts      mini authorization server: user tokens, client credentials, JWKS, token exchange
  idp/http.ts            optional HTTP surface: POST /token, GET /.well-known/jwks.json
  finance-api/api.ts     resource server: JWT verification, RBAC, ABAC, audit log
  finance-api/http.ts    optional HTTP routes + an HTTP FinanceClient
  mcp/agent.ts           DelegatingAgent: actor credential + one exchange per call
  mcp/server.ts          createServer(): MCP tools, no transport
  world.ts               fictional users, clients and budgets
  index.ts               stdio entry point
  demo.ts                prints what each persona can and cannot do through the agent
test/                    node:test suites (see below)
```

Personas (fictional): **Vera**, viewer on cost center CC-100. **Ari**, approver on CC-100 and CC-200. CC-300 belongs to neither.

## Run it

```bash
npm install
npm run demo        # personas x tools, then the audit log
npm test            # all suites
npm run typecheck
npm run build
```

Run the MCP server over stdio (for the MCP Inspector or a client):

```bash
DEMO_USER=ari.approver npm run dev
# or: DEMO_USER=vera.viewer npx @modelcontextprotocol/inspector tsx src/index.ts
```

### Where the user's token comes from

- **Streamable HTTP (recommended in production):** the MCP client sends the user's token in the `Authorization: Bearer` header. With the SDK's bearer-auth middleware, it arrives in tool handlers as `extra.authInfo.token`, which this server uses first. That token's audience must be the MCP server itself.
- **stdio:** the server reads `USER_TOKEN` from its environment. The in-process IdP generates a fresh key on every start, so a token minted elsewhere will not verify. For local play, `DEMO_USER=<sub>` issues one at startup.

With no user token, every tool refuses. The agent never falls back to its own authority.

## What the tests prove

- `test/exchange.test.ts`: `sub`, `act`, single `aud`; roles and cost centers copied from the user; scope intersection; wider requests narrowed, never widened; a scope the user lacks is refused; the agent's allowed scopes cap the result; nested delegation keeps the actor chain and never widens scope, attributes or lifetime; expired, forged, tampered and wrong-audience subject tokens rejected; expired, forged or user-as-actor actor tokens rejected; a disallowed agent and a disallowed audience rejected.
- `test/finance-api.test.ts`: bad signature, wrong issuer, wrong audience, expired and client-only tokens get 401; RBAC (scope and role) and ABAC denials get 403; audit entries carry user and actor for allowed and denied calls.
- `test/mcp.test.ts` (MCP over `InMemoryTransport`): the viewer reads only CC-100 and cannot approve; the approver approves only within CC-100 and CC-200; no user, or the agent's own client token, means refusal; errors are `isError` with clear reasons and never contain token material; annotations are accurate.
- `test/invariant.test.ts`: loops over persona × tool × cost center and asserts that the agent's outcome equals the user's direct outcome against the API with their own token, in fresh worlds per comparison. It also checks that the result isn't vacuous (some calls allowed, some denied).
- `test/http.test.ts`: the same flow over real HTTP. Form-encoded `/token` exchange, the API fetching keys from the JWKS URL, the routes, `WWW-Authenticate` on 401.

## Swapping in a real IdP (not tested)

The agent depends only on `TokenService` (`clientCredentials`, `exchange`) and the API only on an issuer, an audience and a JWKS URL. To use a real provider:

1. Register the MCP server as a confidential client that may perform token exchange or on-behalf-of, and register the finance API as a resource with its own audience and scopes.
2. Implement `TokenService.exchange` as a form POST to the provider's token endpoint. Some providers implement RFC 8693 directly (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`). Others offer an equivalent "on-behalf-of" grant with different parameter names, in which the client authenticates with its secret or certificate instead of an `actor_token`.
3. Point `FinanceApi` at the provider's issuer and `jwks_uri` (from its OpenID discovery document).
4. Map claims: providers differ in how they express roles, groups and custom attributes like `cost_centers`, and in whether and how they emit `act`. If `act` is absent, the agent's identity usually shows up as a client id claim (`azp`, `client_id` or similar). Adjust `authenticate()` and the audit accordingly.

Okta and Microsoft Entra ID both document token-exchange or on-behalf-of flows. Check the current documentation of your provider. Nothing here has been run against either.

## Limitations

- The demo IdP is **not** a production authorization server: one in-memory key, plaintext client secrets, no login UI, no consent, no PKCE, no discovery document.
- Out of scope: key rotation, token revocation and introspection, refresh tokens, sender-constrained tokens (mTLS or DPoP), rate limiting, persistent audit storage.
- The agent fetches a fresh actor token per call. A real one would cache it until shortly before it expires.
- `get_budget` returns 404 for unknown ids but 403 for budgets in other cost centers, which reveals that an id exists. Return 404 for both if that matters to you.
- Scopes and roles are coarse on purpose. Real policies (amount limits, separation of duties, "cannot approve your own request") belong in the same resource-server checks.

## References (by number and title)

- RFC 8693, OAuth 2.0 Token Exchange
- RFC 7519, JSON Web Token (JWT)
- RFC 8707, Resource Indicators for OAuth 2.0

## License

MIT
