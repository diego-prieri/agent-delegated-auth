#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './mcp/server.js';
import { createWorld, userTokenForAgent } from './world.js';

/**
 * stdio entry point. The IdP and finance API run in-process with a fresh
 * signing key each start, so a USER_TOKEN minted elsewhere will not verify.
 * For local play, set DEMO_USER=vera.viewer or ari.approver and one is issued
 * at startup. In a real deployment USER_TOKEN (or, over HTTP, the
 * Authorization header) comes from the user's own sign-in to a real IdP.
 */
const world = await createWorld();
let userToken = process.env.USER_TOKEN;
if (!userToken && process.env.DEMO_USER) userToken = await userTokenForAgent(world.idp, process.env.DEMO_USER);

const server = createServer({ agent: world.agent, finance: world.api, userToken: () => userToken });
await server.connect(new StdioServerTransport());
// stdout carries the protocol; logs must go to stderr.
console.error(`agent-delegated-auth running on stdio (${userToken ? 'user token present' : 'no user token: every tool will refuse'})`);
