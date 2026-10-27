import { AuthorizationServer, type Client, type User } from './idp/authServer.js';
import { FinanceApi, type Budget } from './finance-api/api.js';
import { DelegatingAgent } from './mcp/agent.js';

/** Fictional fixtures shared by the demo, the stdio entry point and the tests. */

export const ISSUER = 'https://idp.example.test';
export const FINANCE_AUDIENCE = 'https://finance-api.example.test';
/** The audience a user's token must carry to be handed to the agent (the MCP server's resource id). */
export const MCP_AUDIENCE = 'https://mcp.example.test/finance-assistant';
export const SUB_AGENT_AUDIENCE = 'https://sub-agent.example.test';

export const USERS: User[] = [
  { sub: 'vera.viewer', name: 'Vera (viewer, CC-100)', scopes: ['budgets:read'], roles: ['viewer'], costCenters: ['CC-100'] },
  { sub: 'ari.approver', name: 'Ari (approver, CC-100 + CC-200)', scopes: ['budgets:read', 'budgets:approve'], roles: ['approver'], costCenters: ['CC-100', 'CC-200'] },
];

export const AGENT = { clientId: 'finance-agent', secret: 'demo-agent-secret' };

export const CLIENTS: Client[] = [
  {
    ...AGENT,
    allowedScopes: ['budgets:read', 'budgets:approve'],
    canExchange: true,
    allowedAudiences: [FINANCE_AUDIENCE, SUB_AGENT_AUDIENCE],
    acceptedSubjectAudiences: [MCP_AUDIENCE],
  },
  // A downstream helper the main agent may delegate to. Read-only by policy.
  { clientId: 'report-sub-agent', secret: 'demo-sub-secret', allowedScopes: ['budgets:read'], canExchange: true, allowedAudiences: [FINANCE_AUDIENCE], acceptedSubjectAudiences: [SUB_AGENT_AUDIENCE] },
  // Registered, but not trusted to act for users.
  { clientId: 'untrusted-bot', secret: 'demo-bot-secret', allowedScopes: ['budgets:read'], canExchange: false, allowedAudiences: [FINANCE_AUDIENCE], acceptedSubjectAudiences: [MCP_AUDIENCE] },
];

export const BUDGETS: Budget[] = [
  {
    id: 'B-100', costCenter: 'CC-100', name: 'Engineering tooling', allocated: 120000, spent: 81500,
    requests: [
      { id: 'R-101', description: 'CI runners upgrade', amount: 9000, status: 'pending' },
      { id: 'R-102', description: 'Design tool seats', amount: 2400, status: 'approved', approvedBy: 'ari.approver' },
    ],
  },
  { id: 'B-200', costCenter: 'CC-200', name: 'Field marketing', allocated: 80000, spent: 30250, requests: [{ id: 'R-201', description: 'Trade show booth', amount: 15000, status: 'pending' }] },
  { id: 'B-300', costCenter: 'CC-300', name: 'Executive travel', allocated: 50000, spent: 12000, requests: [{ id: 'R-301', description: 'Offsite venue', amount: 7000, status: 'pending' }] },
];

export interface World {
  idp: AuthorizationServer;
  api: FinanceApi;
  agent: DelegatingAgent;
}

export async function createWorld(opts: { now?: () => number } = {}): Promise<World> {
  const idp = await AuthorizationServer.create({ issuer: ISSUER, users: USERS, clients: CLIENTS, now: opts.now });
  const api = new FinanceApi({ issuer: ISSUER, audience: FINANCE_AUDIENCE, jwks: idp.jwks(), budgets: BUDGETS, now: opts.now });
  const agent = new DelegatingAgent(idp, AGENT, FINANCE_AUDIENCE);
  return { idp, api, agent };
}

/** A user's token as the MCP client would present it after the user signs in. */
export const userTokenForAgent = (idp: AuthorizationServer, sub: string) => idp.issueUserToken(sub, { audience: MCP_AUDIENCE, clientId: 'mcp-client' });
/** A user's token for calling the finance API directly, with no agent involved. */
export const userTokenForApi = (idp: AuthorizationServer, sub: string) => idp.issueUserToken(sub, { audience: FINANCE_AUDIENCE, clientId: 'finance-web' });
