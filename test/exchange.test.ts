import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeJwt } from 'jose';
import { OAuthError, TOKEN_EXCHANGE_GRANT, type AccessTokenClaims } from '../src/idp/authServer.js';
import { AGENT, FINANCE_AUDIENCE, ISSUER, MCP_AUDIENCE, SUB_AGENT_AUDIENCE, userTokenForAgent, userTokenForApi } from '../src/world.js';
import { forgerIdp, testWorld } from './helpers.js';

const claims = (t: string) => decodeJwt(t) as AccessTokenClaims;
const rejects = (p: Promise<unknown>, code: OAuthError['code'], msg?: RegExp) =>
  assert.rejects(p, (e: unknown) => e instanceof OAuthError && e.code === code && (!msg || msg.test(e.description)));

async function setup() {
  const w = await testWorld();
  const actorToken = await w.idp.clientCredentials(AGENT.clientId, AGENT.secret);
  const ari = await userTokenForAgent(w.idp, 'ari.approver');
  const vera = await userTokenForAgent(w.idp, 'vera.viewer');
  const exchange = (subjectToken: string, more: { scope?: string; audience?: string; actorToken?: string } = {}) =>
    w.idp.exchange({ grantType: TOKEN_EXCHANGE_GRANT, subjectToken, actorToken: more.actorToken ?? actorToken, audience: more.audience ?? FINANCE_AUDIENCE, scope: more.scope });
  return { ...w, actorToken, ari, vera, exchange };
}

test('exchanged token: sub is the user, act names the agent, aud is only the requested API', async () => {
  const { ari, exchange } = await setup();
  const out = await exchange(ari, { scope: 'budgets:read' });
  const c = claims(out.access_token);
  assert.equal(c.sub, 'ari.approver');
  assert.deepEqual(c.act, { sub: AGENT.clientId });
  assert.equal(c.aud, FINANCE_AUDIENCE);
  assert.equal(typeof c.aud, 'string', 'single audience, not an array');
  assert.equal(c.iss, ISSUER);
  assert.equal(c.client_id, AGENT.clientId);
  assert.equal(out.issued_token_type, 'urn:ietf:params:oauth:token-type:access_token');
});

test('roles and cost_centers are copied from the user, never from the agent', async () => {
  const { ari, vera, exchange } = await setup();
  assert.deepEqual(
    [claims((await exchange(ari)).access_token), claims((await exchange(vera)).access_token)].map((c) => [c.roles, c.cost_centers]),
    [
      [['approver'], ['CC-100', 'CC-200']],
      [['viewer'], ['CC-100']],
    ],
  );
});

test('scope is the intersection of requested, user and agent scopes', async () => {
  const { idp, exchange } = await setup();
  // User token narrowed to read only at sign-in: the agent cannot get approve back.
  const narrowAri = await idp.issueUserToken('ari.approver', { audience: MCP_AUDIENCE, clientId: 'mcp-client', scope: 'budgets:read' });
  assert.equal((await exchange(narrowAri, { scope: 'budgets:read budgets:approve' })).scope, 'budgets:read');
  // No scope requested -> everything both hold.
  assert.equal((await exchange(narrowAri)).scope, 'budgets:read');
});

test('a wider requested scope is narrowed, never widened', async () => {
  const { vera, ari, exchange } = await setup();
  const out = await exchange(vera, { scope: 'budgets:read budgets:approve admin:all' });
  assert.equal(out.scope, 'budgets:read');
  assert.equal(claims(out.access_token).scope, 'budgets:read');
  // Even for a user who holds approve: scopes neither user nor agent have are dropped.
  assert.equal((await exchange(ari, { scope: 'budgets:approve admin:all' })).scope, 'budgets:approve');
});

test('a scope the user lacks entirely is refused (invalid_scope), not granted', async () => {
  const { vera, exchange } = await setup();
  await rejects(exchange(vera, { scope: 'budgets:approve' }), 'invalid_scope');
});

test('the agent\'s allowed scopes cap the result even if the user has more', async () => {
  const { idp, ari } = await setup();
  const subActor = await idp.clientCredentials('report-sub-agent', 'demo-sub-secret');
  // report-sub-agent only accepts tokens addressed to it; mint one via the main agent first.
  const mainActor = await idp.clientCredentials(AGENT.clientId, AGENT.secret);
  const hop1 = await idp.exchange({ subjectToken: ari, actorToken: mainActor, audience: SUB_AGENT_AUDIENCE });
  assert.equal(hop1.scope, 'budgets:read budgets:approve');
  const hop2 = await idp.exchange({ subjectToken: hop1.access_token, actorToken: subActor, audience: FINANCE_AUDIENCE, scope: 'budgets:read budgets:approve' });
  assert.equal(hop2.scope, 'budgets:read', 'sub-agent is read-only by policy');
});

test('nested delegation keeps the actor chain and never widens scope, audience or attributes', async () => {
  const { idp, ari } = await setup();
  const mainActor = await idp.clientCredentials(AGENT.clientId, AGENT.secret);
  const subActor = await idp.clientCredentials('report-sub-agent', 'demo-sub-secret');
  const hop1 = await idp.exchange({ subjectToken: ari, actorToken: mainActor, audience: SUB_AGENT_AUDIENCE, scope: 'budgets:read' });
  const hop2 = await idp.exchange({ subjectToken: hop1.access_token, actorToken: subActor, audience: FINANCE_AUDIENCE, scope: 'budgets:read budgets:approve' });
  const c1 = claims(hop1.access_token);
  const c2 = claims(hop2.access_token);
  assert.equal(c2.sub, 'ari.approver');
  assert.deepEqual(c2.act, { sub: 'report-sub-agent', act: { sub: AGENT.clientId } });
  assert.equal(c2.scope, 'budgets:read', 'approve was dropped at hop 1 and cannot come back');
  assert.deepEqual([c2.roles, c2.cost_centers], [c1.roles, c1.cost_centers]);
  assert.ok(c2.exp <= c1.exp, 'nested token never outlives its subject token');
  // The final token is for the finance API, so it cannot be exchanged again by an agent expecting MCP-audience tokens.
  await rejects(idp.exchange({ subjectToken: hop2.access_token, actorToken: mainActor, audience: FINANCE_AUDIENCE }), 'invalid_grant', /audience/);
});

test('exchanged token is short-lived and never outlives the subject token', async () => {
  const { ari, clock, exchange, idp } = await setup();
  assert.equal((await exchange(ari)).expires_in, 300);
  clock.t += 3600 - 60; // the 1h user token has 60s left
  const actor = await idp.clientCredentials(AGENT.clientId, AGENT.secret);
  assert.equal((await exchange(ari, { actorToken: actor })).expires_in, 60);
});

test('expired subject token is rejected', async () => {
  const { ari, clock, exchange, idp } = await setup();
  clock.t += 3601;
  const actor = await idp.clientCredentials(AGENT.clientId, AGENT.secret); // fresh, so the subject is what fails
  await rejects(exchange(ari, { actorToken: actor }), 'invalid_grant', /subject token is expired/);
});

test('expired actor token is rejected', async () => {
  const { ari, clock, exchange } = await setup();
  clock.t += 301;
  await rejects(exchange(ari), 'invalid_grant', /actor token is expired/);
});

test('forged subject token (right issuer name, wrong key) is rejected', async () => {
  const { exchange } = await setup();
  const forged = await userTokenForAgent(await forgerIdp(), 'ari.approver');
  await rejects(exchange(forged), 'invalid_grant', /subject token has an invalid signature/);
});

test('tampered subject token (claims edited) is rejected', async () => {
  const { vera, exchange } = await setup();
  const [h, p, s] = vera.split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  payload.roles = ['approver'];
  payload.cost_centers = ['CC-100', 'CC-200', 'CC-300'];
  const tampered = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
  await rejects(exchange(tampered), 'invalid_grant', /invalid signature/);
});

test('subject token with the wrong audience is rejected (not issued to this agent)', async () => {
  const { idp, exchange } = await setup();
  await rejects(exchange(await userTokenForApi(idp, 'ari.approver')), 'invalid_grant', /audience/);
  await rejects(exchange(await idp.issueUserToken('ari.approver', { audience: 'https://other.example.test', clientId: 'x' })), 'invalid_grant', /audience/);
});

test('a client token cannot be used as the subject (no user = nothing to delegate)', async () => {
  const { actorToken, exchange } = await setup();
  await rejects(exchange(actorToken), 'invalid_grant');
});

test('a user token cannot be used as the actor token', async () => {
  const { ari, exchange } = await setup();
  await rejects(exchange(ari, { actorToken: ari }), 'invalid_client');
});

test('missing actor token is refused', async () => {
  const { ari, idp } = await setup();
  await rejects(idp.exchange({ subjectToken: ari, actorToken: '', audience: FINANCE_AUDIENCE }), 'invalid_request', /actor_token/);
});

test('forged actor token is refused', async () => {
  const { ari, exchange } = await setup();
  const forgedActor = await (await forgerIdp()).clientCredentials(AGENT.clientId, AGENT.secret);
  await rejects(exchange(ari, { actorToken: forgedActor }), 'invalid_grant', /actor token/);
});

test('an agent not allowed to exchange is rejected', async () => {
  const { idp, ari, exchange } = await setup();
  const bot = await idp.clientCredentials('untrusted-bot', 'demo-bot-secret');
  await rejects(exchange(ari, { actorToken: bot }), 'unauthorized_client');
});

test('wrong client secret fails client authentication', async () => {
  const { idp } = await setup();
  await rejects(idp.clientCredentials(AGENT.clientId, 'wrong'), 'invalid_client');
});

test('an audience the agent may not target is rejected', async () => {
  const { ari, exchange } = await setup();
  await rejects(exchange(ari, { audience: 'https://payroll.example.test' }), 'invalid_target');
  await rejects(exchange(ari, { audience: ISSUER }), 'invalid_target');
});

test('only the token-exchange grant and access_token types are accepted', async () => {
  const { idp, ari, actorToken } = await setup();
  await rejects(idp.exchange({ grantType: 'password', subjectToken: ari, actorToken, audience: FINANCE_AUDIENCE }), 'unsupported_grant_type');
  await rejects(idp.exchange({ subjectToken: ari, subjectTokenType: 'urn:ietf:params:oauth:token-type:id_token', actorToken, audience: FINANCE_AUDIENCE }), 'invalid_request');
});

test('JWKS exposes only public key material', async () => {
  const { idp } = await setup();
  const [key] = idp.jwks().keys;
  assert.equal(key.d, undefined);
  assert.equal(key.alg, 'ES256');
});

test('user token issuance never exceeds the user\'s own scopes', async () => {
  const { idp } = await setup();
  const t = await idp.issueUserToken('vera.viewer', { audience: MCP_AUDIENCE, clientId: 'mcp-client', scope: 'budgets:read budgets:approve' });
  assert.equal(claims(t).scope, 'budgets:read');
});
