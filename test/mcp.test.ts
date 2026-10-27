import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AGENT, userTokenForAgent, userTokenForApi } from '../src/world.js';
import { mcpClient, testWorld, text } from './helpers.js';

async function as(sub: string | undefined) {
  const w = await testWorld();
  const token = sub ? await userTokenForAgent(w.idp, sub) : undefined;
  return { ...w, client: await mcpClient(w, token) };
}

const call = (client: any, name: string, args: Record<string, unknown> = {}) => client.callTool({ name, arguments: args });

test('tools and annotations: approve is neither read-only nor idempotent', async () => {
  const { client } = await as('vera.viewer');
  const { tools } = await client.listTools();
  const a = Object.fromEntries(tools.map((t) => [t.name, [t.annotations?.readOnlyHint, t.annotations?.idempotentHint]]));
  assert.deepEqual(a, { list_budgets: [true, true], get_budget: [true, true], approve_budget_request: [false, false], get_audit_log: [true, true] });
});

test('viewer: lists and reads budgets in own cost center only', async () => {
  const { client } = await as('vera.viewer');
  const list = await call(client, 'list_budgets');
  assert.deepEqual((list.structuredContent as any).budgets.map((b: any) => b.id), ['B-100']);
  const get = await call(client, 'get_budget', { budget_id: 'B-100' });
  assert.equal(get.isError, undefined);
  assert.match(text(get), /R-101 \[pending\]/);
});

test('viewer: cannot see other cost centers', async () => {
  const { client } = await as('vera.viewer');
  for (const [name, args] of [['get_budget', { budget_id: 'B-200' }], ['list_budgets', { cost_center: 'CC-300' }]] as const) {
    const r = await call(client, name, args);
    assert.equal(r.isError, true);
    assert.match(text(r), /not permitted for this user .*No access to cost center CC-[23]00/);
  }
});

test('viewer: cannot approve, with a clear reason', async () => {
  const { client, api } = await as('vera.viewer');
  const r = await call(client, 'approve_budget_request', { request_id: 'R-101' });
  assert.equal(r.isError, true);
  assert.match(text(r), /does not hold the permission/);
  assert.equal(api.audit.length, 0, 'refused at the token exchange, never reached the API');
});

test('approver: approves within own cost centers, not outside', async () => {
  const { client } = await as('ari.approver');
  assert.match(text(await call(client, 'approve_budget_request', { request_id: 'R-101' })), /Approved R-101/);
  assert.match(text(await call(client, 'approve_budget_request', { request_id: 'R-201' })), /Approved R-201/);
  const outside = await call(client, 'approve_budget_request', { request_id: 'R-301' });
  assert.equal(outside.isError, true);
  assert.match(text(outside), /CC-300/);
});

test('approve is not idempotent: second approval is a conflict', async () => {
  const { client } = await as('ari.approver');
  await call(client, 'approve_budget_request', { request_id: 'R-101' });
  const again = await call(client, 'approve_budget_request', { request_id: 'R-101' });
  assert.equal(again.isError, true);
  assert.match(text(again), /already approved/);
});

test('no user token: every tool refuses, the agent never uses its own authority', async () => {
  const { client, api } = await as(undefined);
  for (const [name, args] of [['list_budgets', {}], ['get_budget', { budget_id: 'B-100' }], ['approve_budget_request', { request_id: 'R-101' }], ['get_audit_log', {}]] as const) {
    const r = await call(client, name, args);
    assert.equal(r.isError, true);
    assert.match(text(r), /no user is signed in/);
  }
  assert.equal(api.audit.length, 0);
});

test('the agent\'s own client token passed as the "user" token is refused', async () => {
  const w = await testWorld();
  const client = await mcpClient(w, await w.idp.clientCredentials(AGENT.clientId, AGENT.secret));
  const r = await call(client, 'list_budgets');
  assert.equal(r.isError, true);
  assert.match(text(r), /refused to delegate/);
});

test('a user token minted for the API (not the agent) is refused at exchange', async () => {
  const w = await testWorld();
  const client = await mcpClient(w, await userTokenForApi(w.idp, 'ari.approver'));
  const r = await call(client, 'list_budgets');
  assert.equal(r.isError, true);
  assert.match(text(r), /invalid_grant: subject_token audience/);
});

test('expired user session: actionable error', async () => {
  const w = await testWorld();
  const client = await mcpClient(w, await userTokenForAgent(w.idp, 'ari.approver'));
  w.clock.t += 3601;
  const r = await call(client, 'list_budgets');
  assert.equal(r.isError, true);
  assert.match(text(r), /expired.*sign in again/);
});

test('errors never leak tokens', async () => {
  const w = await testWorld();
  const userToken = await userTokenForAgent(w.idp, 'vera.viewer');
  const client = await mcpClient(w, userToken);
  const results = [
    await call(client, 'approve_budget_request', { request_id: 'R-101' }),
    await call(client, 'get_budget', { budget_id: 'B-300' }),
    await call(client, 'get_budget', { budget_id: 'nope' }),
  ];
  w.clock.t += 3601;
  results.push(await call(client, 'list_budgets'));
  for (const r of results) {
    assert.equal(r.isError, true);
    const s = JSON.stringify(r);
    assert.ok(!s.includes('eyJ'), `token-like content leaked: ${s}`);
    assert.ok(!s.includes(userToken.split('.')[2]));
  }
});

test('audit log through the agent shows the user and the agent', async () => {
  const { client } = await as('ari.approver');
  await call(client, 'approve_budget_request', { request_id: 'R-201' });
  const log = await call(client, 'get_audit_log');
  assert.match(text(log), /ari\.approver via finance-agent approve_request request:R-201 allowed/);
});

test('invalid input is rejected before any exchange', async () => {
  const { client, api } = await as('ari.approver');
  const r = await call(client, 'get_budget', { budget_id: '' });
  assert.equal(r.isError, true);
  assert.equal(api.audit.length, 0);
});

test('a token on extra.authInfo (HTTP transport) takes precedence over the stdio fallback', async () => {
  const { resolveUserToken } = await import('../src/mcp/server.js');
  assert.equal(resolveUserToken({ authInfo: { token: 'from-header' } }, () => 'from-env'), 'from-header');
  assert.equal(resolveUserToken({}, () => 'from-env'), 'from-env');
  assert.equal(resolveUserToken({}), undefined);
});
