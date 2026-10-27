import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { decodeJwt } from 'jose';
import { createServer } from './mcp/server.js';
import { USERS, createWorld, userTokenForAgent } from './world.js';

const world = await createWorld();

async function connectAs(userToken: string | undefined) {
  const [c, s] = InMemoryTransport.createLinkedPair();
  await createServer({ agent: world.agent, finance: world.api, userToken: () => userToken }).connect(s);
  const client = new Client({ name: 'demo', version: '0.0.0' });
  await client.connect(c);
  return client;
}

const CALLS: Array<[string, Record<string, string>]> = [
  ['list_budgets', {}],
  ['get_budget', { budget_id: 'B-100' }],
  ['get_budget', { budget_id: 'B-200' }],
  ['get_budget', { budget_id: 'B-300' }],
  ['approve_budget_request', { request_id: 'R-101' }],
  ['approve_budget_request', { request_id: 'R-201' }],
  ['approve_budget_request', { request_id: 'R-301' }],
];

for (const user of USERS) {
  console.log(`\n=== ${user.name}: roles=${user.roles} scopes="${user.scopes.join(' ')}" cost_centers=${user.costCenters}`);
  const token = await userTokenForAgent(world.idp, user.sub);
  const sample = await world.agent.tokenFor(token, 'budgets:read');
  const { sub, aud, scope, act, roles, cost_centers } = decodeJwt(sample);
  console.log(`  exchanged token (claims only): ${JSON.stringify({ sub, aud, scope, act, roles, cost_centers })}`);
  const client = await connectAs(token);
  for (const [name, args] of CALLS) {
    const res: any = await client.callTool({ name, arguments: args });
    const first = String(res.content[0].text).split('\n')[0];
    console.log(`  ${res.isError ? 'DENY' : 'OK  '} ${name}(${Object.values(args).join(', ')}) -> ${first}`);
  }
}

console.log('\n=== The agent alone (its own client credential, no user)');
const actorOnly = await world.agent.actorToken();
try {
  await world.api.listBudgets(actorOnly);
} catch (e) {
  console.log(`  DENY finance API with agent token -> ${(e as Error).message}`);
}
const anon: any = await (await connectAs(undefined)).callTool({ name: 'list_budgets', arguments: {} });
console.log(`  DENY list_budgets without a user -> ${anon.content[0].text}`);

console.log('\n=== Finance API audit log (every entry names the user AND the agent)');
for (const e of world.api.audit) {
  console.log(`  ${e.user.padEnd(13)} via ${(e.actors.join(' <- ') || '(direct)').padEnd(14)} ${e.action.padEnd(16)} ${e.resource.padEnd(18)} ${e.outcome}${e.reason ? ` (${e.reason})` : ''}`);
}
