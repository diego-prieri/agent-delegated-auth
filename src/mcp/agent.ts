import type { ExchangeRequest, TokenResponse } from '../idp/authServer.js';
import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from '../idp/authServer.js';

/** What the agent needs from an authorization server. AuthorizationServer implements it in-process. */
export interface TokenService {
  clientCredentials(clientId: string, secret: string): Promise<string>;
  exchange(req: ExchangeRequest): Promise<TokenResponse>;
}

export interface AgentCredentials {
  clientId: string;
  secret: string;
}

/**
 * The agent's side of delegation. It holds its OWN credential (which by
 * itself opens nothing downstream) and swaps "user token + my credential"
 * for a short-lived token scoped to one API and one call's needs.
 */
export class DelegatingAgent {
  constructor(
    private tokens: TokenService,
    private creds: AgentCredentials,
    private downstreamAudience: string,
  ) {}

  get clientId(): string {
    return this.creds.clientId;
  }

  /** Fetched per call for simplicity. A real agent would cache until shortly before exp. */
  actorToken(): Promise<string> {
    return this.tokens.clientCredentials(this.creds.clientId, this.creds.secret);
  }

  /** One exchange per tool call, asking only for the scope that call needs (least privilege). */
  async tokenFor(userToken: string, scope: string): Promise<string> {
    const res = await this.tokens.exchange({
      grantType: TOKEN_EXCHANGE_GRANT,
      subjectToken: userToken,
      subjectTokenType: ACCESS_TOKEN_TYPE,
      actorToken: await this.actorToken(),
      actorTokenType: ACCESS_TOKEN_TYPE,
      audience: this.downstreamAudience,
      scope,
    });
    return res.access_token;
  }
}
