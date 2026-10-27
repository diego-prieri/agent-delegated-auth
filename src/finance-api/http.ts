import type { IncomingMessage, ServerResponse } from 'node:http';
import { ApiError, type AuditEntry, type Budget, type BudgetRequest, type FinanceApi, type FinanceClient } from './api.js';

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

const bearer = (req: IncomingMessage) => /^Bearer (.+)$/i.exec(req.headers.authorization ?? '')?.[1];

/**
 * GET  /budgets[?cost_center=CC]
 * GET  /budgets/:id
 * POST /requests/:id/approve
 * GET  /audit
 */
export function createFinanceHandler(api: FinanceApi) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const token = bearer(req) ?? '';
      let m: RegExpExecArray | null;
      if (req.method === 'GET' && url.pathname === '/budgets') return json(res, 200, await api.listBudgets(token, url.searchParams.get('cost_center') ?? undefined));
      if (req.method === 'GET' && (m = /^\/budgets\/([^/]+)$/.exec(url.pathname))) return json(res, 200, await api.getBudget(token, decodeURIComponent(m[1])));
      if (req.method === 'POST' && (m = /^\/requests\/([^/]+)\/approve$/.exec(url.pathname))) return json(res, 200, await api.approveRequest(token, decodeURIComponent(m[1])));
      if (req.method === 'GET' && url.pathname === '/audit') return json(res, 200, await api.getAuditLog(token));
      return json(res, 404, { error: 'not_found', message: 'No such route.' });
    } catch (e) {
      if (e instanceof ApiError) return json(res, e.status, { error: e.status === 401 ? 'invalid_token' : e.status === 403 ? 'insufficient_scope' : 'conflict', message: e.message }, e.status === 401 ? { 'www-authenticate': 'Bearer error="invalid_token"' } : {});
      return json(res, 500, { error: 'server_error' });
    }
  };
}

/** FinanceClient over HTTP, so the MCP server can run against a remote API. */
export class HttpFinanceClient implements FinanceClient {
  constructor(private baseUrl: string) {}

  private async request<T>(token: string, path: string, method = 'GET'): Promise<T> {
    const res = await fetch(new URL(path, this.baseUrl), { method, headers: { authorization: `Bearer ${token}` } });
    const body = (await res.json()) as any;
    if (!res.ok) {
      if ([401, 403, 404, 409].includes(res.status)) throw new ApiError(res.status as 401, body.message ?? res.statusText);
      throw new Error(`${method} ${path} failed: ${res.status}`);
    }
    return body as T;
  }

  listBudgets(token: string, costCenter?: string): Promise<Budget[]> {
    return this.request(token, costCenter ? `/budgets?cost_center=${encodeURIComponent(costCenter)}` : '/budgets');
  }
  getBudget(token: string, id: string): Promise<Budget> {
    return this.request(token, `/budgets/${encodeURIComponent(id)}`);
  }
  approveRequest(token: string, id: string): Promise<{ budget: Budget; request: BudgetRequest }> {
    return this.request(token, `/requests/${encodeURIComponent(id)}/approve`, 'POST');
  }
  getAuditLog(token: string): Promise<AuditEntry[]> {
    return this.request(token, '/audit');
  }
}
