import { SignJWT, exportJWK, generateKeyPair, createLocalJWKSet, jwtVerify, errors, type JWK, type JWTPayload, type CryptoKey } from 'jose';

/**
 * A deliberately small, in-process authorization server. It is a teaching
 * tool, not a product: one signing key, users and clients in memory, no
 * refresh tokens, no revocation. What it does do faithfully is the part that
 * matters for delegation — RFC 8693 token exchange that can only ever narrow.
 */

export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const ALG = 'ES256';

/** RFC 8693 §4.1: `act` names the current actor; a nested `act` names the prior one. */
export interface ActorClaim {
  sub: string;
  act?: ActorClaim;
}

export interface AccessTokenClaims extends JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  /** Space-delimited, as in RFC 8693 / RFC 6749. */
  scope: string;
  /** "access" for anything carrying a user; "client" for an agent's own credential. */
  token_use: 'access' | 'client';
  client_id: string;
  roles?: string[];
  /** ABAC attribute: the cost centers this user may touch. */
  cost_centers?: string[];
  act?: ActorClaim;
}

export interface User {
  sub: string;
  name: string;
  /** The most the user can ever be granted. */
  scopes: string[];
  roles: string[];
  costCenters: string[];
}

export interface Client {
  clientId: string;
  secret: string;
  /** Scopes this client may ever hold on a user's behalf. */
  allowedScopes: string[];
  /** May this client use the token-exchange grant at all? */
  canExchange: boolean;
  /** Audiences it may request in an exchange (downstream APIs). */
  allowedAudiences: string[];
  /** Subject tokens it will accept: their `aud` must be one of these (usually its own id). */
  acceptedSubjectAudiences: string[];
}

export interface ExchangeRequest {
  grantType?: string;
  subjectToken: string;
  subjectTokenType?: string;
  actorToken: string;
  actorTokenType?: string;
  /** RFC 8693 `audience` (or an RFC 8707 `resource`): exactly one target. */
  audience: string;
  /** Space-delimited. Omitted means "everything I am allowed, intersected". */
  scope?: string;
}

export interface TokenResponse {
  access_token: string;
  issued_token_type: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

/** RFC 6749 §5.2-style error. `description` is safe to show; it never contains a token. */
export class OAuthError extends Error {
  constructor(
    public readonly code: 'invalid_request' | 'invalid_grant' | 'invalid_client' | 'unauthorized_client' | 'invalid_scope' | 'invalid_target' | 'unsupported_grant_type',
    public readonly description: string,
  ) {
    super(`${code}: ${description}`);
  }
}

export interface AuthServerOptions {
  issuer: string;
  users: User[];
  clients: Client[];
  /** Seconds since epoch. Injectable so tests can expire tokens deterministically. */
  now?: () => number;
  userTokenTtl?: number;
  exchangedTokenTtl?: number;
}

export const splitScope = (s: string | undefined): string[] => (s ? s.split(' ').filter(Boolean) : []);
const intersect = (a: string[], ...rest: string[][]) => [...new Set(a)].filter((x) => rest.every((r) => r.includes(x)));

export class AuthorizationServer {
  readonly issuer: string;
  private users = new Map<string, User>();
  private clients = new Map<string, Client>();
  private now: () => number;
  private userTokenTtl: number;
  private exchangedTokenTtl: number;
  private keyId = 'demo-key-1';
  private privateKey!: CryptoKey;
  private publicJwk!: JWK;
  private jti = 0;

  private constructor(opts: AuthServerOptions) {
    this.issuer = opts.issuer;
    for (const u of opts.users) this.users.set(u.sub, u);
    for (const c of opts.clients) this.clients.set(c.clientId, c);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.userTokenTtl = opts.userTokenTtl ?? 3600;
    this.exchangedTokenTtl = opts.exchangedTokenTtl ?? 300;
  }

  static async create(opts: AuthServerOptions): Promise<AuthorizationServer> {
    const as = new AuthorizationServer(opts);
    const { privateKey, publicKey } = await generateKeyPair(ALG, { extractable: true });
    as.privateKey = privateKey;
    as.publicJwk = { ...(await exportJWK(publicKey)), kid: as.keyId, alg: ALG, use: 'sig' };
    return as;
  }

  /** What /.well-known/jwks.json serves. Public key only. */
  jwks(): { keys: JWK[] } {
    return { keys: [this.publicJwk] };
  }

  private async sign(claims: Omit<AccessTokenClaims, 'iss' | 'iat' | 'jti' | 'exp'>, ttl: number, capExp?: number): Promise<{ token: string; exp: number }> {
    const iat = this.now();
    const exp = Math.min(iat + ttl, capExp ?? Infinity);
    const token = await new SignJWT({ ...claims, iss: this.issuer, iat, exp, jti: `t-${++this.jti}` })
      .setProtectedHeader({ alg: ALG, kid: this.keyId, typ: 'at+jwt' })
      .sign(this.privateKey);
    return { token, exp };
  }

  /**
   * Stands in for an interactive login (authorization code + PKCE in real
   * life). The user gets a token for one audience, with at most their own scopes.
   */
  async issueUserToken(sub: string, opts: { audience: string; clientId: string; scope?: string }): Promise<string> {
    const user = this.users.get(sub);
    if (!user) throw new OAuthError('invalid_grant', `Unknown user ${sub}.`);
    const scopes = opts.scope === undefined ? user.scopes : intersect(splitScope(opts.scope), user.scopes);
    const { token } = await this.sign(
      { sub, aud: opts.audience, scope: scopes.join(' '), token_use: 'access', client_id: opts.clientId, roles: user.roles, cost_centers: user.costCenters },
      this.userTokenTtl,
    );
    return token;
  }

  /** Client credentials grant: the agent's own identity. Audience is the AS itself, so no API accepts it. */
  async clientCredentials(clientId: string, secret: string): Promise<string> {
    const client = this.clients.get(clientId);
    if (!client || client.secret !== secret) throw new OAuthError('invalid_client', 'Client authentication failed.');
    const { token } = await this.sign({ sub: clientId, aud: this.issuer, scope: '', token_use: 'client', client_id: clientId }, this.exchangedTokenTtl);
    return token;
  }

  private async verifyOwn(token: string, what: string): Promise<AccessTokenClaims> {
    try {
      const { payload } = await jwtVerify(token, createLocalJWKSet(this.jwks()), {
        issuer: this.issuer,
        algorithms: [ALG],
        currentDate: new Date(this.now() * 1000),
      });
      return payload as AccessTokenClaims;
    } catch (e) {
      const reason = e instanceof errors.JWTExpired ? 'is expired' : e instanceof errors.JWTClaimValidationFailed ? `failed claim check (${e.claim})` : 'has an invalid signature or format';
      throw new OAuthError('invalid_grant', `The ${what} ${reason}.`);
    }
  }

  /**
   * RFC 8693 token exchange. The output can only be narrower than the input:
   *   sub    = the subject token's sub (the user) — never the agent
   *   act    = { sub: agent, act: <subject token's act, if any> }
   *   aud    = exactly the one requested audience, if this client may target it
   *   scope  = requested ∩ subject token scope ∩ client allowed scopes
   *   roles / cost_centers = copied from the subject token — never from the agent
   *   exp    = min(now + short TTL, subject token exp)
   */
  async exchange(req: ExchangeRequest): Promise<TokenResponse> {
    if (req.grantType !== undefined && req.grantType !== TOKEN_EXCHANGE_GRANT) throw new OAuthError('unsupported_grant_type', `Only ${TOKEN_EXCHANGE_GRANT} is supported.`);
    if (req.subjectTokenType !== undefined && req.subjectTokenType !== ACCESS_TOKEN_TYPE) throw new OAuthError('invalid_request', 'subject_token_type must be an access_token.');
    if (req.actorTokenType !== undefined && req.actorTokenType !== ACCESS_TOKEN_TYPE) throw new OAuthError('invalid_request', 'actor_token_type must be an access_token.');
    if (!req.subjectToken) throw new OAuthError('invalid_request', 'subject_token is required.');
    if (!req.actorToken) throw new OAuthError('invalid_request', 'actor_token is required: delegation needs an identified actor.');
    if (!req.audience) throw new OAuthError('invalid_target', 'audience is required.');

    const actor = await this.verifyOwn(req.actorToken, 'actor token');
    if (actor.token_use !== 'client' || actor.aud !== this.issuer) throw new OAuthError('invalid_client', 'actor_token must be a client credential issued to the actor.');
    const client = this.clients.get(actor.sub);
    if (!client) throw new OAuthError('invalid_client', 'Unknown actor client.');
    if (!client.canExchange) throw new OAuthError('unauthorized_client', `Client ${client.clientId} is not allowed to use token exchange.`);

    const subject = await this.verifyOwn(req.subjectToken, 'subject token');
    if (subject.token_use !== 'access') throw new OAuthError('invalid_grant', 'subject_token must represent a user, not a client.');
    if (!client.acceptedSubjectAudiences.includes(subject.aud)) {
      throw new OAuthError('invalid_grant', `subject_token audience is not ${client.acceptedSubjectAudiences.join(' or ')}; it was not issued to this actor.`);
    }
    if (!client.allowedAudiences.includes(req.audience)) throw new OAuthError('invalid_target', `Client ${client.clientId} may not request tokens for ${req.audience}.`);

    const available = intersect(splitScope(subject.scope), client.allowedScopes);
    const granted = req.scope === undefined ? available : intersect(splitScope(req.scope), available);
    if (granted.length === 0) throw new OAuthError('invalid_scope', 'None of the requested scopes are held by both the user and the actor.');

    const act: ActorClaim = subject.act ? { sub: client.clientId, act: subject.act } : { sub: client.clientId };
    const { token, exp } = await this.sign(
      {
        sub: subject.sub,
        aud: req.audience,
        scope: granted.join(' '),
        token_use: 'access',
        client_id: client.clientId,
        roles: subject.roles ?? [],
        cost_centers: subject.cost_centers ?? [],
        act,
      },
      this.exchangedTokenTtl,
      subject.exp,
    );
    return { access_token: token, issued_token_type: ACCESS_TOKEN_TYPE, token_type: 'Bearer', expires_in: exp - this.now(), scope: granted.join(' ') };
  }
}
