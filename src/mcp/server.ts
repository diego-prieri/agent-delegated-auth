import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { ApiError, type Budget, type FinanceClient } from '../finance-api/api.js';
import { OAuthError } from '../idp/authServer.js';
import type { DelegatingAgent } from './agent.js';

export const SERVER_INFO = { name: 'agent-delegated-auth', version: '0.1.0' };

export interface McpDeps {
  agent: DelegatingAgent;
  finance: FinanceClient;
  /**
   * Where the calling user's token comes from when the transport does not
   * carry one. Over Streamable HTTP, the SDK's bearer-auth middleware puts the
   * Authorization header on `extra.authInfo.token`, which wins. For the stdio
   * demo this reads USER_TOKEN.
   */
  userToken?: () => string | undefined;
}

/** HTTP transport (extra.authInfo, set by the SDK's bearer-auth middleware) wins over the stdio fallback. */
export function resolveUserToken(extra: { authInfo?: { token: string } }, fallback?: () => string | undefined): string | undefined {
  return extra.authInfo?.token ?? fallback?.();
}

function ok(text: string, structuredContent: Record<string, unknown>): CallToolResult {
  return { content: [{ type: 'text', text }], structuredContent };
}

/** Errors are tool results the model can read and explain. They never echo a token. */
function fail(message: string): CallToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function explain(e: unknown, doing: string): CallToolResult {
  if (e instanceof OAuthError && e.code === 'invalid_scope') return fail(`Could not ${doing}: the signed-in user does not hold the permission this action needs, so it cannot be delegated to the agent.`);
  if (e instanceof OAuthError) return fail(`Could not ${doing}: the authorization server refused to delegate (${e.code}: ${e.description}). Ask the user to sign in again if their session expired.`);
  if (e instanceof ApiError) {
    if (e.status === 403) return fail(`Could not ${doing}: not permitted for this user — ${e.message} The agent can only do what the signed-in user is allowed to do.`);
    if (e.status === 401) return fail(`Could not ${doing}: the finance API rejected the delegated token (${e.message}).`);
    return fail(`Could not ${doing}: ${e.message}`);
  }
  return fail(`Could not ${doing}: unexpected error.`);
}

const fmt = (n: number) => n.toLocaleString('en-US');
const summary = (b: Budget) => `${b.id} [${b.costCenter}] ${b.name}: ${fmt(b.spent)} / ${fmt(b.allocated)} spent, ${b.requests.filter((r) => r.status === 'pending').length} pending request(s)`;

export function createServer(deps: McpDeps): McpServer {
  const server = new McpServer(SERVER_INFO, {
    instructions:
      'Finance assistant acting on behalf of the signed-in user. Every call runs with that user\'s permissions, never more. Use list_budgets to discover ids. Ask the user before approve_budget_request.',
  });

  /** Resolve the user, exchange for a call-specific token, run. */
  async function asUser<T>(extra: { authInfo?: { token: string } }, scope: string, doing: string, run: (token: string) => Promise<T>, render: (v: T) => CallToolResult) {
    const userToken = resolveUserToken(extra, deps.userToken);
    if (!userToken) return fail(`Could not ${doing}: no user is signed in. This agent never acts on its own authority; connect with a user access token.`);
    try {
      const delegated = await deps.agent.tokenFor(userToken, scope);
      return render(await run(delegated));
    } catch (e) {
      return explain(e, doing);
    }
  }

  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

  server.registerTool(
    'list_budgets',
    {
      title: 'List budgets',
      description: 'List budgets the signed-in user can see, optionally for one cost center. Only the user\'s own cost centers are ever returned.',
      inputSchema: { cost_center: z.string().min(1).max(64).optional().describe('Cost center id, e.g. CC-100') },
      annotations: readOnly,
    },
    (args, extra) =>
      asUser(extra, 'budgets:read', 'list budgets', (t) => deps.finance.listBudgets(t, args.cost_center), (budgets) =>
        ok(budgets.length ? budgets.map(summary).join('\n') : 'No budgets visible to this user.', { budgets }),
      ),
  );

  server.registerTool(
    'get_budget',
    {
      title: 'Get budget',
      description: 'Get one budget with its requests. Use list_budgets first if you do not know the id.',
      inputSchema: { budget_id: z.string().min(1).max(64).describe('Budget id, e.g. B-100') },
      annotations: readOnly,
    },
    ({ budget_id }, extra) =>
      asUser(extra, 'budgets:read', `get budget ${budget_id}`, (t) => deps.finance.getBudget(t, budget_id), (budget) =>
        ok([summary(budget), ...budget.requests.map((r) => `  ${r.id} [${r.status}] ${r.description}: ${fmt(r.amount)}`)].join('\n'), { budget }),
      ),
  );

  server.registerTool(
    'approve_budget_request',
    {
      title: 'Approve budget request',
      description: 'Approve a pending budget request as the signed-in user. Requires the approver role and access to the request\'s cost center. Fails if already approved.',
      inputSchema: { request_id: z.string().min(1).max(64).describe('Budget request id, e.g. R-101') },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    ({ request_id }, extra) =>
      asUser(extra, 'budgets:approve', `approve ${request_id}`, (t) => deps.finance.approveRequest(t, request_id), ({ budget, request }) =>
        ok(`Approved ${request.id} (${fmt(request.amount)}) on ${budget.id} [${budget.costCenter}].`, { request, budget }),
      ),
  );

  server.registerTool(
    'get_audit_log',
    {
      title: 'Get audit log',
      description: 'Show the finance API\'s audit entries for the signed-in user, including which agent acted on their behalf.',
      inputSchema: {},
      annotations: readOnly,
    },
    (_args, extra) =>
      asUser(extra, 'budgets:read', 'read the audit log', (t) => deps.finance.getAuditLog(t), (entries) =>
        ok(
          entries.length
            ? entries.map((e) => `${e.at} ${e.user} via ${e.actors.join(' <- ') || '(direct)'} ${e.action} ${e.resource} ${e.outcome}${e.reason ? ` (${e.reason})` : ''}`).join('\n')
            : 'No audit entries.',
          { entries },
        ),
      ),
  );

  return server;
}
