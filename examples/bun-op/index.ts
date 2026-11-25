// A complete OpenID Provider (authorization code flow) built only from oidc-primitive.
// The library does the security checks; this file is the host: routes, storage, sessions, UI.
// Every step cites the spec section it satisfies. Dev-only: synthetic users, automatic consent.
import { Database } from 'bun:sqlite';
import {
	AccessToken,
	AccessTokenVerifier,
	ClientAssertion,
	Bearer,
	UserClaims,
	ClientSecret,
	IdToken,
	Introspection,
	Keys,
	ServerMetadata,
	OAuthError,
	OAuthResponse,
	Pkce,
	Redacted,
	RedirectUri,
	Resource,
	Scope,
	OpaqueToken,
	TokenSigner,
} from 'oidc-primitive';

export interface ClientConfig {
	client_id: string;
	client_secret?: string;
	redirect_uris: string[];
	token_endpoint_auth_method:
		| 'client_secret_basic'
		| 'client_secret_post'
		| 'private_key_jwt'
		| 'none';
	jwks_uri?: string;
	pkce?: 'required' | 'oidc-nonce';
	grant_types?: string[];
	post_logout_redirect_uris?: string[];
}

export interface Config {
	issuer: string;
	port: number;
	database: string;
	clients: ClientConfig[];
}

export const fromEnv = (): Config => ({
	issuer: process.env.ISSUER ?? 'http://localhost:3000',
	port: Number(process.env.PORT ?? 3000),
	database: process.env.DATABASE ?? ':memory:',
	clients: process.env.CLIENTS
		? JSON.parse(process.env.CLIENTS)
		: [
				{
					client_id: 'demo',
					redirect_uris: ['http://127.0.0.1:3001/callback'],
					token_endpoint_auth_method: 'none',
				},
			],
});

interface Client {
	client_id: string;
	secretHash?: string;
	/** private_key_jwt: the client's registered keys (RFC 7523 s3). */
	keys?: Keys.VerifyKey;
	redirect_uris: string[];
	method: ClientConfig['token_endpoint_auth_method'];
	pkce?: 'required' | 'oidc-nonce';
	grant_types: string[];
}

/** Everything decided at /authorize; kept under the code, then copied into the grant. */
interface Grant {
	client_id: string;
	redirect_uri: string;
	username: string;
	sub: string;
	scope: string[];
	nonce?: string;
	challenge?: string;
	pkce_required: boolean;
	audience: string;
	claims: UserClaims.Request;
	auth_time: number;
	include_auth_time: boolean;
	acr?: string;
	grant_id: string;
}

const scopesSupported = ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'];
const claimsSupported = [
	'sub',
	'iss',
	'auth_time',
	'acr',
	'name',
	'given_name',
	'family_name',
	'preferred_username',
	'email',
	'email_verified',
	'address',
	'phone_number',
	'phone_number_verified',
	'updated_at',
];
const accessTtl = AccessToken.defaultLifetime; // seconds, the lifetime TokenSigner uses by default
const codeTtl = 60; // checklist: authorization codes live 60 s or less
const refreshTtl = 30 * 24 * 3600;
const spentTtl = 24 * 3600;

const now = (): number => Math.floor(Date.now() / 1000);
const esc = (s: string): string =>
	s.replace(
		/[&<>"']/g,
		(c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
	);

// Checklist: login and error pages must not be framed and must not leak the URL.
const pageHeaders = {
	'Content-Type': 'text/html; charset=utf-8',
	'Content-Security-Policy': "frame-ancestors 'none'",
	'X-Frame-Options': 'DENY',
	'Referrer-Policy': 'no-referrer',
	'Cache-Control': 'no-store',
};
const page = (title: string, body: string, status = 200): Response =>
	new Response(`<!doctype html><meta charset="utf-8"><title>${esc(title)}</title>${body}`, {
		status,
		headers: pageHeaders,
	});
// RFC 9700 s4.11.2: never redirect to an unverified redirect_uri; show the error instead.
const errorPage = (message: string): Response =>
	page(
		'Invalid authorization request',
		`<h1>Invalid authorization request</h1><p>${esc(message)}</p>`,
		400,
	);

const userClaims = (username: string, sub: string): Record<string, unknown> => ({
	sub,
	name: `${username} Example`,
	given_name: username,
	family_name: 'Example',
	middle_name: 'Middle',
	nickname: username,
	preferred_username: username,
	profile: `https://op.test/users/${encodeURIComponent(username)}`,
	picture: 'https://op.test/picture.png',
	website: 'https://op.test',
	gender: 'nonbinary',
	birthdate: '2000-01-01',
	zoneinfo: 'Asia/Bangkok',
	locale: 'th-TH',
	email: `${username}@example.com`,
	email_verified: true,
	address: { formatted: '1 Example Street, Bangkok, Thailand' },
	phone_number: '+66 81 234 5678',
	phone_number_verified: true,
	updated_at: 1700000000,
});

export const start = async (config: Config): Promise<Bun.Server<undefined>> => {
	const issuer = config.issuer.replace(/\/+$/, '');
	const base = new URL(issuer).pathname.replace(/\/$/, '');
	const secure = issuer.startsWith('https:') ? '; Secure' : '';

	const clients = new Map<string, Client>();
	for (const c of config.clients) {
		if (c.token_endpoint_auth_method === 'private_key_jwt' && !c.jwks_uri) {
			throw new Error(`client ${c.client_id}: jwks_uri is required for private_key_jwt`);
		}
		if (
			['client_secret_basic', 'client_secret_post'].includes(c.token_endpoint_auth_method) &&
			!c.client_secret
		) {
			throw new Error(
				`client ${c.client_id}: client_secret is required for ${c.token_endpoint_auth_method}`,
			);
		}
		for (const uri of c.redirect_uris) RedirectUri.validate(uri);
		clients.set(c.client_id, {
			client_id: c.client_id,
			// RFC 6749 s10.10: only the hash of the secret is kept.
			secretHash: c.client_secret ? await OpaqueToken.hash(c.client_secret) : undefined,
			keys: c.jwks_uri ? Keys.remoteResolver(c.jwks_uri) : undefined,
			redirect_uris: c.redirect_uris,
			method: c.token_endpoint_auth_method,
			pkce: c.pkce,
			grant_types: c.grant_types ?? ['authorization_code', 'refresh_token'],
		});
	}

	const db = new Database(config.database);
	db.run(`
		CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY, data TEXT NOT NULL, exp INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS spent(hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, exp INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, data TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
		CREATE TABLE IF NOT EXISTS refresh(hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, exp INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS assertions(client_id TEXT NOT NULL, jti TEXT NOT NULL, exp INTEGER NOT NULL, PRIMARY KEY (client_id, jti));
		CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, username TEXT NOT NULL, sub TEXT NOT NULL, auth_time INTEGER NOT NULL);
	`);
	// shortcut: expired rows are never swept; add a periodic DELETE for a long-running deployment.

	// Signing key. RS256 is what OIDC suite clients expect. shortcut: regenerated at every start; persist for real use.
	const { publicKey, privateKey } = await Keys.generate('RS256');
	const kid = 'op-1';
	const signer = TokenSigner.make({ issuer, key: privateKey, kid, alg: 'RS256' });
	const jwks = await Keys.jwks([{ key: publicKey, kid, alg: 'RS256' }]);
	// A public CryptoKey is a valid VerifyKey, so no jose resolver is needed.
	const verifier = AccessTokenVerifier.make({ issuer, audience: issuer, keys: publicKey });

	const url = (path: string): string => `${issuer}${path}`;
	const metadata: ServerMetadata.AuthorizationServerMetadata = ServerMetadata.make({
		issuer,
		endpoints: {
			authorization: url('/authorize'),
			token: url('/token'),
			jwksUri: url('/jwks'),
			userinfo: url('/userinfo'),
			introspection: url('/introspect'),
			revocation: url('/revoke'),
		},
		scopesSupported,
		claimsSupported,
		grantTypesSupported: ['authorization_code', 'refresh_token', 'client_credentials'],
		tokenEndpointAuthMethodsSupported: [
			'client_secret_basic',
			'client_secret_post',
			'private_key_jwt',
			'none',
		],
		idTokenSigningAlgValuesSupported: ['RS256'],
		claimsParameterSupported: true,
	});

	// ---- storage helpers -------------------------------------------------------------------------

	type Session = { username: string; sub: string; auth_time: number };
	const session = async (req: Request): Promise<Session | undefined> => {
		const sid = req.headers
			.get('cookie')
			?.split(/;\s*/)
			.find((c) => c.startsWith('sid='))
			?.slice(4);
		if (!sid) return undefined;
		return (db
			.query('SELECT username, sub, auth_time FROM sessions WHERE hash = ?')
			.get(await OpaqueToken.hash(sid)) ?? undefined) as Session | undefined;
	};
	const revokeGrant = (id: string): void =>
		void db.query('UPDATE grants SET revoked = 1 WHERE id = ?').run(id);
	const grantOf = (id: string): Grant | undefined => {
		const row = db.query('SELECT data, revoked FROM grants WHERE id = ?').get(id) as {
			data: string;
			revoked: number;
		} | null;
		return row && !row.revoked ? (JSON.parse(row.data) as Grant) : undefined;
	};
	const form = async (req: Request): Promise<URLSearchParams> =>
		new URLSearchParams(await req.text());

	// ---- authorization endpoint (OIDC Core s3.1.2) ----------------------------------------------

	const authorize = async (req: Request, u: URL): Promise<Response> => {
		const p = req.method === 'POST' ? await form(req) : u.searchParams;
		const client = clients.get(p.get('client_id') ?? '');
		const redirectUri = p.get('redirect_uri');
		// RFC 9700 s4.11.2 / OIDC Core s3.1.2.6: unknown client or unregistered redirect_uri -> error page, never a redirect.
		if (!client || !redirectUri || !RedirectUri.matches(redirectUri, client.redirect_uris)) {
			return errorPage('Unknown client or unregistered redirect_uri.');
		}
		const state = p.get('state') ?? undefined;
		try {
			return await authorizeChecked(req, p, client, redirectUri, state);
		} catch (err) {
			// RFC 6749 s4.1.2.1 + RFC 9207: errors go back to the verified redirect_uri with `iss`.
			if (err instanceof OAuthError.OAuthError)
				return err.toRedirect(redirectUri, { state, issuer });
			throw err;
		}
	};

	const authorizeChecked = async (
		req: Request,
		p: URLSearchParams,
		client: Client,
		redirectUri: string,
		state: string | undefined,
	): Promise<Response> => {
		if (p.has('request'))
			throw new OAuthError.RequestNotSupported('request objects are not supported'); // OIDC Core s6.1
		if (p.has('request_uri'))
			throw new OAuthError.RequestUriNotSupported('request_uri is not supported'); // s6.2
		if (p.has('registration'))
			throw new OAuthError.RegistrationNotSupported('registration is not supported'); // s7.2.1
		if (p.get('response_type') !== 'code')
			throw new OAuthError.UnsupportedResponseType('only response_type=code');
		if (!client.grant_types.includes('authorization_code')) {
			throw new OAuthError.UnauthorizedClient('client may not use the authorization code flow');
		}
		const mode = p.get('response_mode');
		if (mode !== null && mode !== 'query')
			throw new OAuthError.InvalidRequest('only response_mode=query');

		// RFC 6749 s3.3: unknown scopes are dropped, not fatal.
		const scope = Scope.parse(p.get('scope')).filter((s) => scopesSupported.includes(s));
		const nonce = p.get('nonce') ?? undefined;

		// PKCE (RFC 7636 s4.3, RFC 9700 s2.1.1, design D13): a confidential `oidc-nonce` client may skip it
		// (nonce is still echoed and bound into the ID token when the client sends one; the Basic plan
		// requires a nonce-less request from a confidential client to succeed).
		const challenge = p.get('code_challenge') ?? undefined;
		const exempt = client.pkce === 'oidc-nonce' && client.method !== 'none';
		if (challenge !== undefined) {
			Pkce.validateMethod(p.get('code_challenge_method'));
			if (!Pkce.isChallenge(challenge))
				throw new OAuthError.InvalidRequest('code_challenge is malformed');
		} else if (!exempt) {
			throw new OAuthError.InvalidRequest('PKCE with code_challenge_method=S256 is required');
		}

		const audience = Resource.resolveAudience(p.getAll('resource'), issuer); // RFC 8707 s2
		const claims = UserClaims.parseRequest(p.get('claims')); // OIDC Core s5.5

		const prompts = (p.get('prompt') ?? '').split(' ').filter(Boolean);
		if (prompts.includes('none') && prompts.length > 1)
			throw new OAuthError.InvalidRequest('prompt=none is exclusive');
		const maxAgeParam = p.get('max_age');
		const maxAge = maxAgeParam === null ? undefined : Number(maxAgeParam);
		if (maxAge !== undefined && !(Number.isInteger(maxAge) && maxAge >= 0)) {
			throw new OAuthError.InvalidRequest('max_age must be a non-negative integer');
		}

		// OIDC Core s3.1.2.1: id_token_hint is checked with the OP's own key; expiry is tolerated.
		const hintJwt = p.get('id_token_hint');
		const hint = hintJwt
			? await IdToken.verify(hintJwt, {
					issuer,
					audience: client.client_id,
					keys: publicKey,
					allowExpired: true,
				})
			: undefined;

		const sess = await session(req);
		const needLogin =
			!sess ||
			prompts.includes('login') ||
			(maxAge !== undefined && now() - sess.auth_time > maxAge) ||
			(hint !== undefined && hint.sub !== sess.sub);
		if (needLogin) {
			// OIDC Core s3.1.2.6: prompt=none must never show UI.
			if (prompts.includes('none'))
				throw new OAuthError.LoginRequired('end-user is not authenticated');
			// Strip what has been satisfied by logging in, or we would loop.
			const back = new URLSearchParams(p);
			back.delete('id_token_hint');
			const rest = prompts.filter((x) => x !== 'login');
			if (rest.length) back.set('prompt', rest.join(' '));
			else back.delete('prompt');
			const returnTo = `${base}/authorize?${back}`;
			return new Response(null, {
				status: 303,
				headers: {
					Location: `${base}/login?return_to=${encodeURIComponent(returnTo)}`,
					'Cache-Control': 'no-store',
				},
			});
		}

		// Consent is automatic in this dev provider.
		const code = OpaqueToken.generate();
		const grant: Grant = {
			client_id: client.client_id,
			redirect_uri: redirectUri,
			username: sess.username,
			sub: sess.sub,
			scope,
			nonce,
			challenge,
			pkce_required: !exempt,
			audience,
			claims,
			auth_time: sess.auth_time,
			// OIDC Core s2: auth_time is required when max_age was sent, and when asked for via `claims`.
			include_auth_time:
				maxAge !== undefined || (claims.id_token !== undefined && 'auth_time' in claims.id_token),
			acr: p.get('acr_values')?.split(' ')[0],
			grant_id: Redacted.value(OpaqueToken.generate(16)),
		};
		// RFC 6749 s4.1.2 / checklist: only the hash of the code is stored, with a <= 60 s lifetime.
		db.query('INSERT INTO codes(hash, data, exp) VALUES (?, ?, ?)').run(
			await OpaqueToken.hash(code),
			JSON.stringify(grant),
			now() + codeTtl,
		);
		return OAuthResponse.redirect(redirectUri, { code, state }, { issuer }); // adds iss (RFC 9207)
	};

	// ---- login ---------------------------------------------------------------------------------

	const login = async (req: Request, u: URL): Promise<Response> => {
		const post = req.method === 'POST';
		const p = post ? await form(req) : u.searchParams;
		const returnTo = p.get('return_to') ?? '';
		// Only a local /authorize URL is a valid return target (no open redirect).
		const safe = returnTo.startsWith(`${base}/authorize?`) ? returnTo : undefined;
		if (!post) {
			return page(
				'Sign in',
				`<h1>Sign in</h1><form method="post" action="${esc(`${base}/login`)}">` +
					`<input type="hidden" name="return_to" value="${esc(safe ?? '')}">` +
					`<label>Username <input id="username" name="username" autofocus required></label>` +
					`<button id="submit" type="submit">Sign in</button></form>`,
			);
		}
		const username = (p.get('username') ?? '').trim().slice(0, 100);
		if (!username) return page('Sign in', '<h1>Sign in</h1><p>Username is required.</p>', 400);
		// shortcut: no CSRF token on this dev login form; SameSite=Lax limits cross-site cookie use.
		const sid = Redacted.value(OpaqueToken.generate());
		const sub = await OpaqueToken.hash(`user:${username}`);
		db.query('INSERT INTO sessions(hash, username, sub, auth_time) VALUES (?, ?, ?, ?)').run(
			await OpaqueToken.hash(sid),
			username,
			sub,
			now(),
		);
		const headers = new Headers({
			'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Lax; Path=${base || '/'}${secure}`,
			'Cache-Control': 'no-store',
			'Referrer-Policy': 'no-referrer',
		});
		if (safe) headers.set('Location', safe);
		else return page('Signed in', `<h1>Signed in</h1><p>${esc(username)}</p>`);
		return new Response(null, { status: 303, headers });
	};

	// ---- token endpoint (RFC 6749 s3.2) --------------------------------------------------------

	/** RFC 6749 s2.3 and RFC 7523 s3: the method used must be the one registered for the client. */
	const authenticate = async (req: Request, f: URLSearchParams): Promise<Client> => {
		const basic = ClientSecret.parseBasic(req.headers.get('authorization'));
		// RFC 6749 s5.2: answer with a Basic challenge only when the client tried Basic.
		const fail = (): OAuthError.InvalidClient =>
			new OAuthError.InvalidClient(
				'client authentication failed',
				basic ? { scheme: 'Basic' } : {},
			);
		const assertion = f.get('client_assertion');
		if (assertion !== null) {
			if (f.get('client_assertion_type') !== ClientAssertion.assertionType) throw fail();
			// RFC 6749 s2.3: one authentication method per request.
			if (basic !== undefined || f.has('client_secret')) {
				throw new OAuthError.InvalidRequest('use only one client authentication method');
			}
			// RFC 7521 s4.2: `client_id` is optional with an assertion; the assertion's `sub` names the client.
			// Peek at the unverified payload only to find the candidate; ClientAssertion.verify binds it below.
			const peekSub = (): string | undefined => {
				try {
					// atob is Latin-1; decode the bytes as UTF-8 so a non-ASCII sub still resolves.
					const b64 = assertion.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/');
					const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
					const payload = JSON.parse(new TextDecoder().decode(bytes)) as { sub?: unknown };
					return typeof payload.sub === 'string' ? payload.sub : undefined;
				} catch {
					return undefined;
				}
			};
			const client = clients.get(f.get('client_id') ?? peekSub() ?? '');
			if (!client || client.method !== 'private_key_jwt' || !client.keys) throw fail();
			const { jti, expiresAt } = await ClientAssertion.verify(assertion, {
				issuer,
				clientId: client.client_id,
				keys: client.keys,
			});
			// Checklist: record each assertion jti until it expires and reject a repeat (RFC 7523 s3 item 7).
			const fresh = db
				.query(
					'INSERT INTO assertions(client_id, jti, exp) VALUES (?, ?, ?) ON CONFLICT DO NOTHING RETURNING jti',
				)
				.get(client.client_id, jti, expiresAt);
			if (!fresh) throw fail();
			return client;
		}
		// RFC 6749 s2.3: one authentication method per request, also for Basic plus a body secret.
		if (basic !== undefined && f.has('client_secret')) {
			throw new OAuthError.InvalidRequest('use only one client authentication method');
		}
		const secret = basic ? Redacted.value(basic.clientSecret) : f.get('client_secret');
		const method = basic ? 'client_secret_basic' : secret !== null ? 'client_secret_post' : 'none';
		const client = clients.get(basic?.clientId ?? f.get('client_id') ?? '');
		if (!client || client.method !== method) throw fail();
		if (method !== 'none' && !(await OpaqueToken.matchesHash(secret!, client.secretHash!)))
			throw fail();
		return client;
	};

	const issueTokens = async (g: Grant, scope: string[], withNonce: boolean): Promise<Response> => {
		const access = await signer.signAccessToken({
			sub: g.sub,
			aud: g.audience,
			client_id: g.client_id,
			scope: Scope.format(scope),
			gid: g.grant_id,
		});
		const body: Record<string, unknown> = {
			access_token: access,
			token_type: 'Bearer',
			expires_in: accessTtl,
			scope: Scope.format(scope),
		};
		if (scope.includes('openid')) {
			// OIDC Core s3.1.3.6/s2: aud = client_id, nonce echoed, at_hash binds the ID token to the access token.
			body.id_token = await signer.signIdToken(
				{
					...UserClaims.select(userClaims(g.username, g.sub), {
						scopes: [],
						request: g.claims,
						target: 'id_token',
					}),
					sub: g.sub,
					aud: g.client_id,
					nonce: withNonce ? g.nonce : undefined,
					auth_time: g.include_auth_time ? g.auth_time : undefined,
					acr: g.acr,
				},
				{ accessToken: access },
			);
		}
		if (g.scope.length && clients.get(g.client_id)?.grant_types.includes('refresh_token')) {
			const refresh = OpaqueToken.generate();
			db.query('INSERT INTO refresh(hash, grant_id, exp) VALUES (?, ?, ?)').run(
				await OpaqueToken.hash(refresh),
				g.grant_id,
				now() + refreshTtl,
			);
			body.refresh_token = refresh;
		}
		return OAuthResponse.json(body);
	};

	const token = async (req: Request): Promise<Response> => {
		const f = await form(req);
		const client = await authenticate(req, f);
		const type = f.get('grant_type');
		if (
			type !== null &&
			client.grant_types.includes(type) === false &&
			type !== 'client_credentials'
		) {
			throw new OAuthError.UnauthorizedClient('grant type not allowed for this client');
		}

		if (type === 'authorization_code') {
			const code = f.get('code');
			if (!code) throw new OAuthError.InvalidRequest('code is required');
			const h = await OpaqueToken.hash(code);
			// Checklist: consume atomically. Everything after this point happens only if the delete found the row.
			const row = db.query('DELETE FROM codes WHERE hash = ? RETURNING data, exp').get(h) as {
				data: string;
				exp: number;
			} | null;
			if (!row) {
				// OAuth 2.1 s7.5.3: a spent code replayed -> revoke everything issued from it.
				const spent = db.query('SELECT grant_id FROM spent WHERE hash = ?').get(h) as {
					grant_id: string;
				} | null;
				if (spent) revokeGrant(spent.grant_id);
				throw new OAuthError.InvalidGrant('code is invalid');
			}
			const g = JSON.parse(row.data) as Grant;
			db.query('INSERT INTO spent(hash, grant_id, exp) VALUES (?, ?, ?)').run(
				h,
				g.grant_id,
				now() + spentTtl,
			);
			if (row.exp < now() || g.client_id !== client.client_id)
				throw new OAuthError.InvalidGrant('code is invalid');
			// RFC 6749 s4.1.3: redirect_uri was sent at /authorize, so it must repeat exactly.
			if (f.get('redirect_uri') !== g.redirect_uri)
				throw new OAuthError.InvalidGrant('redirect_uri does not match');
			await Pkce.verify(f.get('code_verifier'), g.challenge, { required: g.pkce_required });
			db.query('INSERT INTO grants(id, data) VALUES (?, ?)').run(g.grant_id, JSON.stringify(g));
			return issueTokens(g, g.scope, true);
		}

		if (type === 'refresh_token') {
			const rt = f.get('refresh_token');
			if (!rt) throw new OAuthError.InvalidRequest('refresh_token is required');
			const h = await OpaqueToken.hash(rt);
			const row = db.query('SELECT grant_id, used, exp FROM refresh WHERE hash = ?').get(h) as {
				grant_id: string;
				used: number;
				exp: number;
			} | null;
			const g = row && grantOf(row.grant_id);
			if (!row || !g || g.client_id !== client.client_id || row.exp < now()) {
				throw new OAuthError.InvalidGrant('refresh_token is invalid');
			}
			// OAuth 2.1 s4.3.1: rotate with compare-and-swap; a rotated token seen again means theft -> revoke the grant.
			const swapped = db.query('UPDATE refresh SET used = 1 WHERE hash = ? AND used = 0').run(h);
			if (swapped.changes === 0) {
				revokeGrant(row.grant_id);
				throw new OAuthError.InvalidGrant('refresh_token is invalid');
			}
			const requested = f.has('scope') ? Scope.parse(f.get('scope')) : g.scope;
			if (!requested.every((s) => g.scope.includes(s)))
				throw new OAuthError.InvalidScope('scope exceeds the grant');
			return issueTokens(g, requested, false); // OIDC Core s12.2: no nonce on refresh
		}

		if (type === 'client_credentials') {
			// RFC 6749 s4.4: confidential clients only, no refresh token, no ID token.
			if (client.method === 'none' || !client.grant_types.includes(type)) {
				throw new OAuthError.UnauthorizedClient('client_credentials not allowed');
			}
			const scope = Scope.parse(f.get('scope')).filter(
				(s) => scopesSupported.includes(s) && s !== 'openid',
			);
			const access = await signer.signAccessToken({
				sub: client.client_id,
				aud: Resource.resolveAudience(f.getAll('resource'), issuer),
				client_id: client.client_id,
				scope: Scope.format(scope),
			});
			return OAuthResponse.json({
				access_token: access,
				token_type: 'Bearer',
				expires_in: accessTtl,
				scope: Scope.format(scope),
			});
		}
		throw new OAuthError.UnsupportedGrantType('unsupported grant_type');
	};

	// ---- userinfo (OIDC Core s5.3) --------------------------------------------------------------

	const userinfo = async (req: Request): Promise<Response> => {
		let bearer = Bearer.parse(req.headers);
		// RFC 6750 s2.2: POST form-encoded body is also allowed.
		if (bearer === undefined && req.method === 'POST')
			bearer = (await form(req)).get('access_token') ?? undefined;
		if (bearer === undefined) throw new OAuthError.InvalidToken();
		const v = await verifier.verify(bearer);
		const gid = v.claims.gid;
		const g = typeof gid === 'string' ? grantOf(gid) : undefined;
		if (!g) throw new OAuthError.InvalidToken('token is invalid'); // revoked grant or client_credentials token
		if (!v.scope.includes('openid')) throw new OAuthError.InsufficientScope('openid');
		return OAuthResponse.json(
			UserClaims.select(userClaims(g.username, g.sub), {
				scopes: v.scope,
				request: g.claims,
				target: 'userinfo',
			}),
		);
	};

	// ---- introspection (RFC 7662) and revocation (RFC 7009) ------------------------------------

	/** The grant and owner behind an access (JWT) or refresh token, if still live. */
	const resolve = async (
		t: string,
	): Promise<
		{ grant: Grant; refresh?: { exp: number }; access?: AccessTokenVerifier.Verified } | undefined
	> => {
		const row = db
			.query('SELECT grant_id, used, exp FROM refresh WHERE hash = ?')
			.get(await OpaqueToken.hash(t)) as { grant_id: string; used: number; exp: number } | null;
		if (row) {
			const grant = grantOf(row.grant_id);
			return grant && !row.used && row.exp > now() ? { grant, refresh: row } : undefined;
		}
		try {
			const access = await verifier.verify(t);
			const grant = typeof access.claims.gid === 'string' ? grantOf(access.claims.gid) : undefined;
			return grant ? { grant, access } : undefined;
		} catch {
			return undefined;
		}
	};

	const introspect = async (req: Request): Promise<Response> => {
		const f = await form(req);
		const client = await authenticate(req, f); // RFC 7662 s2.1: callers must authenticate
		const t = f.get('token');
		const r = t ? await resolve(t) : undefined;
		// Only the client the token was issued to may see it.
		if (!r || r.grant.client_id !== client.client_id)
			return OAuthResponse.json(Introspection.inactive());
		const g = r.grant;
		return OAuthResponse.json(
			Introspection.active(
				r.access
					? {
							scope: r.access.scope.join(' '),
							client_id: g.client_id,
							username: g.username,
							token_type: 'Bearer',
							exp: r.access.claims.exp,
							iat: r.access.claims.iat,
							sub: g.sub,
							aud: r.access.claims.aud,
							iss: issuer,
							jti: r.access.claims.jti,
						}
					: {
							scope: g.scope.join(' '),
							client_id: g.client_id,
							username: g.username,
							exp: r.refresh!.exp,
							sub: g.sub,
							iss: issuer,
						},
			),
		);
	};

	const revoke = async (req: Request): Promise<Response> => {
		const f = await form(req);
		const client = await authenticate(req, f);
		const t = f.get('token');
		const r = t ? await resolve(t) : undefined;
		// RFC 7009 s2.2: 200 even for unknown tokens. Revoking either token kills the whole grant.
		if (r && r.grant.client_id === client.client_id) revokeGrant(r.grant.grant_id);
		return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } });
	};

	// ---- routing -------------------------------------------------------------------------------

	const handle = async (req: Request): Promise<Response> => {
		const u = new URL(req.url);
		const m = req.method;
		// RFC 8414 s3.1: well-known segment inserted before the issuer path.
		if (m === 'GET' && u.pathname === `/.well-known/oauth-authorization-server${base}`)
			return OAuthResponse.json(metadata);
		if (!u.pathname.startsWith(base)) return new Response('not found', { status: 404 });
		const path = u.pathname.slice(base.length);
		const get = m === 'GET';
		const post = m === 'POST';
		if (get && path === '/.well-known/openid-configuration') return OAuthResponse.json(metadata);
		if (get && path === '/jwks') return OAuthResponse.json(jwks);
		if (get && path === '/healthz') return new Response('ok');
		if ((get || post) && path === '/authorize') return authorize(req, u);
		if ((get || post) && path === '/login') return login(req, u);
		if (post && path === '/token') return token(req);
		if ((get || post) && path === '/userinfo') return userinfo(req);
		if (post && path === '/introspect') return introspect(req);
		if (post && path === '/revoke') return revoke(req);
		return new Response('not found', { status: 404 });
	};

	return Bun.serve({
		port: config.port,
		async fetch(req) {
			let res: Response;
			try {
				res = await handle(req);
			} catch (err) {
				if (err instanceof OAuthError.OAuthError) res = err.toResponse();
				else {
					console.error(err);
					res = new OAuthError.ServerError().toResponse();
				}
			}
			console.log(`${req.method} ${new URL(req.url).pathname} ${res.status}`);
			return res;
		},
	});
};

if (import.meta.main) {
	const server = await start(fromEnv());
	console.log(`OP listening on ${server.url} (issuer ${fromEnv().issuer})`);
}
