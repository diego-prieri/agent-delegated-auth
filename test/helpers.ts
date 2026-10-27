import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/mcp/server.js';
import { AuthorizationServer } from '../src/idp/authServer.js';
import { CLIENTS, ISSUER, USERS, createWorld, type World } from '../src/world.js';

/** A controllable clock (seconds). */
export function clock(start = 1_800_000_000) {
  const c = { t: start, now: () => c.t };
  return c;
}

export async function testWorld() {
  const c = clock();
  const world = await createWorld({ now: c.now });
  return { ...world, clock: c };
}

/** Same issuer name, different key: what an attacker minting their own tokens looks like. */
export const forgerIdp = () => AuthorizationServer.create({ issuer: ISSUER, users: USERS, clients: CLIENTS });

export async function mcpClient(world: World, userToken: string | undefined) {
  const [c, s] = InMemoryTransport.createLinkedPair();
  await createServer({ agent: world.agent, finance: world.api, userToken: () => userToken }).connect(s);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(c);
  return client;
}

export const text = (r: any) => r.content[0].text as string;
