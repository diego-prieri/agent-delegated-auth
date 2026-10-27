import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiError, FinanceApi } from '../src/finance-api/api.js';
import { AGENT, BUDGETS, FINANCE_AUDIENCE, ISSUER, MCP_AUDIENCE, userTokenForApi } from '../src/world.js';
import { forgerIdp, testWorld } from './helpers.js';

const status = (p: Promise<unknown>, code: number, msg?: RegExp) =>
  assert.rejects(p, (e: unknown) => e instanceof ApiError && e.status === code && (!msg || msg.test(e.message)));

test('missing token -> 401', async () => {
  const { api } = await testWorld();
  await status(api.listBudgets(''), 401, /Missing/);
});

test('bad signature (forged key) -> 401', async () => {
  const { api } = await testWorld();
  await status(api.listBudgets(await userTokenForApi(await forgerIdp(), 'ari.approver')), 401, /signature/);
});

test('garbage token -> 401', async () => {
  const { api } = await testWorld();
  await status(api.listBudgets('not.a.jwt'), 401);
});

test('wrong issuer -> 401', async () => {
  const { idp, clock } = await testWorld();
  const api = new FinanceApi({ issuer: 'https://some-other-idp.example.test', audience: FINANCE_AUDIENCE, jwks: idp.jwks(), budgets: BUDGETS, now: clock.now });
  await status(api.listBudgets(await userTokenForApi(idp, 'ari.approver')), 401, /wrong issuer/);
});

test('wrong audience -> 401 (a token meant for the agent cannot be replayed at the API)', async () => {
  const { idp, api } = await testWorld();
  const forAgent = await idp.issueUserToken('ari.approver', { audience: MCP_AUDIENCE, clientId: 'mcp-client' });
  await status(api.listBudgets(forAgent), 401, /wrong audience/);
});

test('expired -> 401', async () => {
  const { idp, api, clock } = await testWorld();
  const t = await userTokenForApi(idp, 'ari.approver');
  clock.t += 3601;
  await status(api.listBudgets(t), 401, /expired/);
});

test('the agent\'s own client token -> 401 (no user behind it)', async () => {
  const { idp, api } = await testWorld();
  await status(api.listBudgets(await idp.clientCredentials(AGENT.clientId, AGENT.secret)), 401);
});

test('RBAC: a viewer cannot approve even with a hand-crafted scope request', async () => {
  const { idp, api } = await testWorld();
  // Vera's token cannot carry budgets:approve (issuance intersects with her scopes)...
  await status(api.approveRequest(await userTokenForApi(idp, 'vera.viewer'), 'R-101'), 403, /scope budgets:approve/);
});

test('RBAC: scope alone is not enough, the role must match', async () => {
  const { clock } = await testWorld();
  // An IdP misconfigured to give a viewer the approve scope: the API still checks the role.
  const { AuthorizationServer } = await import('../src/idp/authServer.js');
  const loose = await AuthorizationServer.create({
    issuer: ISSUER, now: clock.now, clients: [],
    users: [{ sub: 'vera.viewer', name: 'v', scopes: ['budgets:read', 'budgets:approve'], roles: ['viewer'], costCenters: ['CC-100'] }],
  });
  const api = new FinanceApi({ issuer: ISSUER, audience: FINANCE_AUDIENCE, jwks: loose.jwks(), budgets: BUDGETS, now: clock.now });
  await status(api.approveRequest(await loose.issueUserToken('vera.viewer', { audience: FINANCE_AUDIENCE, clientId: 'x' }), 'R-101'), 403, /role approver/);
});

test('ABAC: users only see and touch their own cost centers', async () => {
  const { idp, api } = await testWorld();
  const vera = await userTokenForApi(idp, 'vera.viewer');
  const ari = await userTokenForApi(idp, 'ari.approver');
  assert.deepEqual((await api.listBudgets(vera)).map((b) => b.id), ['B-100']);
  assert.deepEqual((await api.listBudgets(ari)).map((b) => b.id), ['B-100', 'B-200']);
  await status(api.listBudgets(vera, 'CC-200'), 403, /CC-200/);
  await status(api.getBudget(vera, 'B-200'), 403, /CC-200/);
  await status(api.approveRequest(ari, 'R-301'), 403, /CC-300/);
  assert.equal((await api.approveRequest(ari, 'R-201')).request.status, 'approved');
});

test('404 and 409 for missing or already-approved requests', async () => {
  const { idp, api } = await testWorld();
  const ari = await userTokenForApi(idp, 'ari.approver');
  await status(api.getBudget(ari, 'B-999'), 404);
  await status(api.approveRequest(ari, 'R-999'), 404);
  await status(api.approveRequest(ari, 'R-102'), 409, /already approved/);
});

test('audit entries name the user and the actor chain, for allowed and denied calls', async () => {
  const { idp, api, agent } = await testWorld();
  const userForAgent = await idp.issueUserToken('ari.approver', { audience: MCP_AUDIENCE, clientId: 'mcp-client' });
  await api.approveRequest(await agent.tokenFor(userForAgent, 'budgets:approve'), 'R-101');
  await status(api.getBudget(await agent.tokenFor(userForAgent, 'budgets:read'), 'B-300'), 403);
  await api.listBudgets(await userTokenForApi(idp, 'vera.viewer'));
  assert.deepEqual(
    api.audit.map(({ user, actors, action, resource, outcome }) => ({ user, actors, action, resource, outcome })),
    [
      { user: 'ari.approver', actors: ['finance-agent'], action: 'approve_request', resource: 'request:R-101', outcome: 'allowed' },
      { user: 'ari.approver', actors: ['finance-agent'], action: 'get_budget', resource: 'budget:B-300', outcome: 'denied' },
      { user: 'vera.viewer', actors: [], action: 'list_budgets', resource: 'budgets', outcome: 'allowed' },
    ],
  );
  assert.equal((await api.getBudget(await userTokenForApi(idp, 'ari.approver'), 'B-100')).requests[0].approvedBy, 'ari.approver', 'the user is the approver of record, not the agent');
});

test('getAuditLog returns only the caller\'s own entries', async () => {
  const { idp, api } = await testWorld();
  await api.listBudgets(await userTokenForApi(idp, 'ari.approver'));
  const mine = await api.getAuditLog(await userTokenForApi(idp, 'vera.viewer'));
  assert.deepEqual(mine, []);
});
