import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { FinanceApi } from '../src/finance-api/api.js';
import { HttpFinanceClient, createFinanceHandler } from '../src/finance-api/http.js';
import { AuthorizationServer, TOKEN_EXCHANGE_GRANT, type ExchangeRequest, type TokenResponse } from '../src/idp/authServer.js';
import { createIdpHandler } from '../src/idp/http.js';
import { DelegatingAgent, type TokenService } from '../src/mcp/agent.js';
import { createServer } from '../src/mcp/server.js';
import { AGENT, BUDGETS, CLIENTS, FINANCE_AUDIENCE, ISSUER, USERS, userTokenForAgent } from '../src/world.js';

const servers: Server[] = [];
after(() => servers.forEach((s) => s.close()));

async function listen(handler: Parameters<typeof createHttpServer>[1]): Promise<string> {
  const s = createHttpServer(handler);
  servers.push(s);
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
}

/** TokenService over the /token endpoint, form-encoded as RFC 8693 specifies. */
class HttpTokenService implements TokenService {
  constructor(private base: string) {}
  private async post(form: Record<string, string>) {
    const res = await fetch(`${this.base}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });
    const body = (await res.json()) as any;
    if (!res.ok) throw new Error(`${body.error}: ${body.error_description}`);
    return body;
  }
  async clientCredentials(clientId: string, secret: string) {
    return (await this.post({ grant_type: 'client_credentials', client_id: clientId, client_secret: secret })).access_token as string;
  }
  async exchange(r: ExchangeRequest): Promise<TokenResponse> {
    return this.post({
      grant_type: TOKEN_EXCHANGE_GRANT, subject_token: r.subjectToken, subject_token_type: r.subjectTokenType!,
      actor_token: r.actorToken, actor_token_type: r.actorTokenType!, audience: r.audience, ...(r.scope && { scope: r.scope }),
    });
  }
}

test('end to end over HTTP: /token exchange, remote JWKS, finance API routes', async () => {
  const idp = await AuthorizationServer.create({ issuer: ISSUER, users: USERS, clients: CLIENTS });
  const idpUrl = await listen(createIdpHandler(idp));
  const jwks = await (await fetch(`${idpUrl}/.well-known/jwks.json`)).json();
  assert.equal((jwks as any).keys.length, 1);

  const api = new FinanceApi({ issuer: ISSUER, audience: FINANCE_AUDIENCE, jwks: new URL(`${idpUrl}/.well-known/jwks.json`), budgets: BUDGETS });
  const apiUrl = await listen(createFinanceHandler(api));

  const agent = new DelegatingAgent(new HttpTokenService(idpUrl), AGENT, FINANCE_AUDIENCE);
  const [c, s] = InMemoryTransport.createLinkedPair();
  const userToken = await userTokenForAgent(idp, 'ari.approver');
  await createServer({ agent, finance: new HttpFinanceClient(apiUrl), userToken: () => userToken }).connect(s);
  const client = new Client({ name: 't', version: '0' });
  await client.connect(c);

  const ok: any = await client.callTool({ name: 'approve_budget_request', arguments: { request_id: 'R-201' } });
  assert.equal(ok.isError, undefined);
  const denied: any = await client.callTool({ name: 'get_budget', arguments: { budget_id: 'B-300' } });
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /CC-300/);
  assert.deepEqual(api.audit.map((e) => [e.user, e.actors[0], e.outcome]), [['ari.approver', 'finance-agent', 'allowed'], ['ari.approver', 'finance-agent', 'denied']]);

  // Raw HTTP: 401 with WWW-Authenticate, and OAuth errors from /token.
  const noAuth = await fetch(`${apiUrl}/budgets`);
  assert.equal(noAuth.status, 401);
  assert.match(noAuth.headers.get('www-authenticate') ?? '', /invalid_token/);
  const badGrant = await fetch(`${idpUrl}/token`, { method: 'POST', body: new URLSearchParams({ grant_type: 'password' }) });
  assert.deepEqual([badGrant.status, ((await badGrant.json()) as any).error], [400, 'unsupported_grant_type']);
});
