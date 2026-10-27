import type { IncomingMessage, ServerResponse } from 'node:http';
import { AuthorizationServer, OAuthError, TOKEN_EXCHANGE_GRANT } from './authServer.js';

export async function readBody(req: IncomingMessage): Promise<string> {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 64 * 1024) throw new Error('body too large');
  }
  return body;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

/**
 * Minimal HTTP surface: GET /.well-known/jwks.json and POST /token
 * (application/x-www-form-urlencoded, grant_type = token-exchange or client_credentials).
 */
export function createIdpHandler(as: AuthorizationServer) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (req.method === 'GET' && url.pathname === '/.well-known/jwks.json') return json(res, 200, as.jwks());
      if (req.method !== 'POST' || url.pathname !== '/token') return json(res, 404, { error: 'not_found' });

      const form = new URLSearchParams(await readBody(req));
      const grant = form.get('grant_type');
      if (grant === 'client_credentials') {
        const token = await as.clientCredentials(form.get('client_id') ?? '', form.get('client_secret') ?? '');
        return json(res, 200, { access_token: token, token_type: 'Bearer' });
      }
      if (grant !== TOKEN_EXCHANGE_GRANT) throw new OAuthError('unsupported_grant_type', 'Unsupported grant_type.');
      const out = await as.exchange({
        grantType: grant,
        subjectToken: form.get('subject_token') ?? '',
        subjectTokenType: form.get('subject_token_type') ?? undefined,
        actorToken: form.get('actor_token') ?? '',
        actorTokenType: form.get('actor_token_type') ?? undefined,
        audience: form.get('audience') ?? form.get('resource') ?? '',
        scope: form.get('scope') ?? undefined,
      });
      return json(res, 200, out);
    } catch (e) {
      if (e instanceof OAuthError) return json(res, e.code === 'invalid_client' ? 401 : 400, { error: e.code, error_description: e.description });
      return json(res, 500, { error: 'server_error' });
    }
  };
}
