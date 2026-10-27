import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiError } from '../src/finance-api/api.js';
import { BUDGETS, USERS, createWorld, userTokenForAgent, userTokenForApi } from '../src/world.js';
import { mcpClient } from './helpers.js';

/**
 * The property this repo exists to demonstrate: for every persona, tool and
 * target, what the agent achieves on the user's behalf equals what the user
 * could achieve directly with their own token — never more. Each comparison
 * uses two fresh worlds so a mutation in one cannot influence the other.
 */

type Outcome = { allowed: true; data: unknown } | { allowed: false };

const COST_CENTERS = [...new Set(BUDGETS.map((b) => b.costCenter)), 'CC-999'];
const targetsFor = (cc: string) => ({
  budget: BUDGETS.find((b) => b.costCenter === cc)?.id ?? 'B-999',
  request: BUDGETS.find((b) => b.costCenter === cc)?.requests.find((r) => r.status === 'pending')?.id ?? 'R-999',
});

const CASES = [
  { tool: 'list_budgets', args: (cc: string) => ({ cost_center: cc }), direct: (api: any, t: string, cc: string) => api.listBudgets(t, cc), pick: (s: any) => s.budgets },
  { tool: 'get_budget', args: (cc: string) => ({ budget_id: targetsFor(cc).budget }), direct: (api: any, t: string, cc: string) => api.getBudget(t, targetsFor(cc).budget), pick: (s: any) => s.budget },
  { tool: 'approve_budget_request', args: (cc: string) => ({ request_id: targetsFor(cc).request }), direct: (api: any, t: string, cc: string) => api.approveRequest(t, targetsFor(cc).request).then((r: any) => r.request), pick: (s: any) => s.request },
] as const;

async function direct(sub: string, c: (typeof CASES)[number], cc: string): Promise<Outcome> {
  const w = await createWorld();
  try {
    return { allowed: true, data: await c.direct(w.api, await userTokenForApi(w.idp, sub), cc) };
  } catch (e) {
    if (e instanceof ApiError) return { allowed: false };
    throw e;
  }
}

async function viaAgent(sub: string, c: (typeof CASES)[number], cc: string): Promise<Outcome> {
  const w = await createWorld();
  const client = await mcpClient(w, await userTokenForAgent(w.idp, sub));
  const r: any = await client.callTool({ name: c.tool, arguments: c.args(cc) });
  return r.isError ? { allowed: false } : { allowed: true, data: c.pick(r.structuredContent) };
}

test('invariant: agent outcome == direct user outcome, for every persona x tool x cost center', async () => {
  let compared = 0;
  let allowedCount = 0;
  for (const user of USERS) {
    for (const c of CASES) {
      for (const cc of COST_CENTERS) {
        const [d, a] = await Promise.all([direct(user.sub, c, cc), viaAgent(user.sub, c, cc)]);
        const label = `${user.sub} ${c.tool} ${cc}`;
        if (a.allowed) assert.ok(d.allowed, `PRIVILEGE ESCALATION: agent succeeded where user could not: ${label}`);
        assert.deepEqual(a, d, label);
        compared++;
        if (d.allowed) allowedCount++;
      }
    }
  }
  assert.equal(compared, USERS.length * CASES.length * COST_CENTERS.length);
  // Guard against a vacuous pass (e.g. everything denied).
  assert.ok(allowedCount >= 5 && allowedCount < compared, `allowed=${allowedCount} of ${compared}`);
});
