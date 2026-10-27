import { createLocalJWKSet, createRemoteJWKSet, errors, jwtVerify, type JWK, type JWTVerifyGetKey } from 'jose';
import type { AccessTokenClaims, ActorClaim } from '../idp/authServer.js';
import { splitScope } from '../idp/authServer.js';

/**
 * The resource server. It trusts nothing the caller says about itself: every
 * decision comes from a verified token. Authorization happens HERE, not in the
 * agent — the agent could be buggy or prompt-injected; the API cannot be talked into anything.
 */

export interface BudgetRequest {
  id: string;
  description: string;
  amount: number;
  status: 'pending' | 'approved';
  approvedBy?: string;
}

export interface Budget {
  id: string;
  costCenter: string;
  name: string;
  allocated: number;
  spent: number;
  requests: BudgetRequest[];
}

export interface AuditEntry {
  at: string;
  user: string;
  /** Actor chain, outermost first: ["finance-agent"] or ["sub-agent", "finance-agent"]. Empty = the user acted directly. */
  actors: string[];
  action: 'list_budgets' | 'get_budget' | 'approve_request' | 'get_audit_log';
  resource: string;
  outcome: 'allowed' | 'denied';
  reason?: string;
}

/** HTTP-flavoured error. 401 = who are you?; 403 = I know who you are, and no; 404/409 = resource state. */
export class ApiError extends Error {
  constructor(
    public readonly status: 401 | 403 | 404 | 409,
    message: string,
  ) {
    super(message);
  }
}

export interface Caller {
  claims: AccessTokenClaims;
  scopes: string[];
}

/** The interface the agent depends on. Implemented in-process by FinanceApi, or over HTTP. */
export interface FinanceClient {
  listBudgets(token: string, costCenter?: string): Promise<Budget[]>;
  getBudget(token: string, budgetId: string): Promise<Budget>;
  approveRequest(token: string, requestId: string): Promise<{ budget: Budget; request: BudgetRequest }>;
  getAuditLog(token: string): Promise<AuditEntry[]>;
}

export interface FinanceApiOptions {
  issuer: string;
  /** This API's identifier. Tokens for any other audience are rejected. */
  audience: string;
  /** Either the JWKS document (in-process) or its URL (fetched and cached by jose). */
  jwks: { keys: JWK[] } | URL;
  budgets: Budget[];
  now?: () => number;
}

/** RBAC: which role unlocks which action. Scope (what the token may do) is checked separately. */
const RBAC: Record<AuditEntry['action'], { scope: string; roles: string[] }> = {
  list_budgets: { scope: 'budgets:read', roles: ['viewer', 'approver'] },
  get_budget: { scope: 'budgets:read', roles: ['viewer', 'approver'] },
  approve_request: { scope: 'budgets:approve', roles: ['approver'] },
  get_audit_log: { scope: 'budgets:read', roles: ['viewer', 'approver'] },
};

const flattenActors = (act: ActorClaim | undefined): string[] => (act ? [act.sub, ...flattenActors(act.act)] : []);

export class FinanceApi implements FinanceClient {
  readonly audit: AuditEntry[] = [];
  private budgets: Budget[];
  private keys: JWTVerifyGetKey;
  private now: () => number;

  constructor(private opts: FinanceApiOptions) {
    this.budgets = structuredClone(opts.budgets);
    this.keys = opts.jwks instanceof URL ? createRemoteJWKSet(opts.jwks) : createLocalJWKSet(opts.jwks);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Signature (via JWKS), issuer, audience, expiry, and token kind. Anything else → 401. */
  async authenticate(token: string | undefined): Promise<Caller> {
    if (!token) throw new ApiError(401, 'Missing bearer token.');
    let claims: AccessTokenClaims;
    try {
      const { payload } = await jwtVerify(token, this.keys, {
        issuer: this.opts.issuer,
        audience: this.opts.audience,
        algorithms: ['ES256'],
        currentDate: new Date(this.now() * 1000),
      });
      claims = payload as AccessTokenClaims;
    } catch (e) {
      if (e instanceof errors.JWTExpired) throw new ApiError(401, 'Token expired.');
      if (e instanceof errors.JWTClaimValidationFailed) throw new ApiError(401, `Token rejected: ${e.claim === 'aud' ? 'wrong audience' : e.claim === 'iss' ? 'wrong issuer' : `invalid ${e.claim}`}.`);
      throw new ApiError(401, 'Token signature or format is invalid.');
    }
    // A client credential identifies an agent, not a person. No user, no access.
    if (claims.token_use !== 'access') throw new ApiError(401, 'Token does not represent a user.');
    return { claims, scopes: splitScope(claims.scope) };
  }

  private record(caller: Caller, action: AuditEntry['action'], resource: string, outcome: AuditEntry['outcome'], reason?: string): void {
    this.audit.push({ at: new Date(this.now() * 1000).toISOString(), user: caller.claims.sub, actors: flattenActors(caller.claims.act), action, resource, outcome, reason });
  }

  private deny(caller: Caller, action: AuditEntry['action'], resource: string, reason: string): never {
    this.record(caller, action, resource, 'denied', reason);
    throw new ApiError(403, reason);
  }

  private rbac(caller: Caller, action: AuditEntry['action'], resource: string): void {
    const rule = RBAC[action];
    if (!caller.scopes.includes(rule.scope)) this.deny(caller, action, resource, `Token lacks scope ${rule.scope}.`);
    if (!(caller.claims.roles ?? []).some((r) => rule.roles.includes(r))) this.deny(caller, action, resource, `Requires role ${rule.roles.join(' or ')}.`);
  }

  /** ABAC: the cost center must be one of the user's own. */
  private abac(caller: Caller, action: AuditEntry['action'], resource: string, costCenter: string): void {
    if (!(caller.claims.cost_centers ?? []).includes(costCenter)) this.deny(caller, action, resource, `No access to cost center ${costCenter}.`);
  }

  async listBudgets(token: string, costCenter?: string): Promise<Budget[]> {
    const caller = await this.authenticate(token);
    const resource = costCenter ? `cost-center:${costCenter}` : 'budgets';
    this.rbac(caller, 'list_budgets', resource);
    if (costCenter) this.abac(caller, 'list_budgets', resource, costCenter);
    const mine = caller.claims.cost_centers ?? [];
    const out = this.budgets.filter((b) => mine.includes(b.costCenter) && (!costCenter || b.costCenter === costCenter));
    this.record(caller, 'list_budgets', resource, 'allowed');
    return structuredClone(out);
  }

  async getBudget(token: string, budgetId: string): Promise<Budget> {
    const caller = await this.authenticate(token);
    const resource = `budget:${budgetId}`;
    this.rbac(caller, 'get_budget', resource);
    const budget = this.budgets.find((b) => b.id === budgetId);
    if (!budget) throw new ApiError(404, `Budget ${budgetId} not found.`);
    this.abac(caller, 'get_budget', resource, budget.costCenter);
    this.record(caller, 'get_budget', resource, 'allowed');
    return structuredClone(budget);
  }

  async approveRequest(token: string, requestId: string): Promise<{ budget: Budget; request: BudgetRequest }> {
    const caller = await this.authenticate(token);
    const resource = `request:${requestId}`;
    this.rbac(caller, 'approve_request', resource);
    const budget = this.budgets.find((b) => b.requests.some((r) => r.id === requestId));
    if (!budget) throw new ApiError(404, `Budget request ${requestId} not found.`);
    this.abac(caller, 'approve_request', resource, budget.costCenter);
    const request = budget.requests.find((r) => r.id === requestId)!;
    if (request.status !== 'pending') throw new ApiError(409, `Budget request ${requestId} is already ${request.status}.`);
    request.status = 'approved';
    request.approvedBy = caller.claims.sub;
    this.record(caller, 'approve_request', resource, 'allowed');
    return structuredClone({ budget, request });
  }

  /** A user sees only audit entries about themselves (including what agents did for them). */
  async getAuditLog(token: string): Promise<AuditEntry[]> {
    const caller = await this.authenticate(token);
    this.rbac(caller, 'get_audit_log', 'audit');
    const mine = this.audit.filter((e) => e.user === caller.claims.sub);
    this.record(caller, 'get_audit_log', 'audit', 'allowed');
    return structuredClone(mine);
  }
}
