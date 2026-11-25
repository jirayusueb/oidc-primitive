// End-to-end check of the example OP: discovery -> authorize (PKCE S256 + nonce) -> login -> token -> userinfo
// -> refresh -> introspect -> revoke, plus code-reuse and refresh-reuse revocation.
import { IdToken, OpaqueToken, Pkce, Redacted } from 'oidc-primitive';
import { start } from './index.ts';

const probe = Bun.serve({ port: 0, fetch: () => new Response() });
const port = probe.port!;
await probe.stop(true);
const issuer = `http://127.0.0.1:${port}`;
const redirect = 'http://127.0.0.1:3001/callback';
const log = console.log;
console.log = () => {}; // silence the server's request log
const server = await start({
	issuer,
	port,
	database: ':memory:',
	clients: [
		{ client_id: 'demo', redirect_uris: [redirect], token_endpoint_auth_method: 'none' },
		{
			client_id: 'svc',
			client_secret: 's3cret',
			redirect_uris: [redirect],
			token_endpoint_auth_method: 'client_secret_basic',
			grant_types: ['client_credentials'],
		},
	],
});

const t0 = performance.now();
const check = (cond: unknown, msg: string): void => {
	if (!cond) throw new Error(`FAIL: ${msg}`);
	log(`ok  ${msg} (${Math.round(performance.now() - t0)} ms)`);
};
const post = (
	path: string,
	body: Record<string, string>,
	headers: Record<string, string> = {},
): Promise<Response> =>
	fetch(issuer + path, {
		method: 'POST',
		redirect: 'manual',
		headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
		body: new URLSearchParams(body),
	});
const payload = (jwt: string): Record<string, unknown> =>
	JSON.parse(atob(jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')));

try {
	const disc = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<
		string,
		any
	>;
	check(
		disc.issuer === issuer && disc.id_token_signing_alg_values_supported[0] === 'RS256',
		'discovery',
	);
	const jwks = (await (await fetch(disc.jwks_uri)).json()) as {
		keys: { alg: string; d?: string }[];
	};
	check(jwks.keys[0]?.alg === 'RS256' && !jwks.keys[0]?.d, 'jwks has public RS256 key only');

	const verifier = Redacted.value(OpaqueToken.generate(32));
	const authz = (extra: Record<string, string> = {}, challenge = true): string =>
		`${issuer}/authorize?` +
		new URLSearchParams({
			response_type: 'code',
			client_id: 'demo',
			redirect_uri: redirect,
			scope: 'openid profile email offline_access',
			state: 'st4te',
			nonce: 'n0nce',
			...(challenge && { code_challenge: challengeOf, code_challenge_method: 'S256' }),
			...extra,
		});
	const challengeOf = await Pkce.deriveChallenge(verifier);

	const bad = await fetch(authz({ redirect_uri: 'https://evil.example/cb' }), {
		redirect: 'manual',
	});
	check(
		bad.status === 400 && (await bad.text()).includes('Invalid authorization request'),
		'bad redirect_uri -> 400 page',
	);
	const noPkce = await fetch(authz({}, false), { redirect: 'manual' });
	check(
		new URL(noPkce.headers.get('location')!).searchParams.get('error') === 'invalid_request',
		'missing PKCE rejected',
	);
	const none = await fetch(authz({ prompt: 'none' }), { redirect: 'manual' });
	check(
		new URL(none.headers.get('location')!).searchParams.get('error') === 'login_required',
		'prompt=none -> login_required',
	);

	const first = await fetch(authz(), { redirect: 'manual' });
	const loginUrl = new URL(first.headers.get('location')!, issuer);
	check(loginUrl.pathname === '/login', 'authorize redirects to login');
	check((await (await fetch(loginUrl)).text()).includes('id="username"'), 'login form served');
	const li = await post('/login', {
		username: 'alice',
		return_to: loginUrl.searchParams.get('return_to')!,
	});
	const cookie = li.headers.getSetCookie()[0]!.split(';')[0]!;
	check(
		li.status === 303 && li.headers.getSetCookie()[0]!.includes('HttpOnly'),
		'login sets HttpOnly session cookie',
	);

	const grant = async (): Promise<URL> => {
		const r = await fetch(new URL(li.headers.get('location')!, issuer), {
			redirect: 'manual',
			headers: { cookie },
		});
		return new URL(r.headers.get('location')!);
	};
	const cb = await grant();
	const code = cb.searchParams.get('code')!;
	check(
		code && cb.searchParams.get('state') === 'st4te' && cb.searchParams.get('iss') === issuer,
		'code, state and iss on redirect',
	);

	const tokenReq = (c: string, v = verifier): Promise<Response> =>
		post('/token', {
			grant_type: 'authorization_code',
			code: c,
			redirect_uri: redirect,
			client_id: 'demo',
			code_verifier: v,
		});
	check((await tokenReq(code, 'x'.repeat(43))).status === 400, 'wrong code_verifier rejected');
	const tr = await tokenReq((await grant()).searchParams.get('code')!);
	const tok = (await tr.json()) as Record<string, string>;
	check(tr.status === 200 && tok.token_type === 'Bearer' && tok.expires_in, 'token response');
	const idt = payload(tok.id_token!);
	check(
		idt.nonce === 'n0nce' && idt.aud === 'demo' && idt.iss === issuer,
		'id_token nonce/aud/iss',
	);
	check(idt.at_hash === (await IdToken.atHash(tok.access_token!, 'RS256')), 'id_token at_hash');

	const ui = await fetch(`${issuer}/userinfo`, {
		headers: { authorization: `Bearer ${tok.access_token}` },
	});
	const info = (await ui.json()) as Record<string, unknown>;
	// OIDC Core s5.4: the email scope grants both email and email_verified.
	check(
		ui.status === 200 &&
			info.sub === idt.sub &&
			info.email === 'alice@example.com' &&
			info.email_verified === true,
		'userinfo',
	);

	const rf = await post('/token', {
		grant_type: 'refresh_token',
		refresh_token: tok.refresh_token!,
		client_id: 'demo',
	});
	const tok2 = (await rf.json()) as Record<string, string>;
	check(
		rf.status === 200 && tok2.refresh_token && tok2.refresh_token !== tok.refresh_token,
		'refresh rotates',
	);

	const intro = (await (
		await post('/introspect', { token: tok2.access_token!, client_id: 'demo' })
	).json()) as Record<string, unknown>;
	check(intro.active === true && intro.sub === idt.sub, 'introspect active');

	// Reuse of the rotated refresh token revokes the whole grant, so the newest token dies too.
	const reuse = await post('/token', {
		grant_type: 'refresh_token',
		refresh_token: tok.refresh_token!,
		client_id: 'demo',
	});
	check(reuse.status === 400, 'refresh reuse rejected');
	const after = (await (
		await post('/introspect', { token: tok2.access_token!, client_id: 'demo' })
	).json()) as Record<string, unknown>;
	check(after.active === false, 'refresh reuse revoked the grant');

	// Code replay revokes tokens issued from it.
	const replay = await tokenReq(code);
	check(replay.status === 400, 'consumed code rejected');
	const c2 = (await grant()).searchParams.get('code')!;
	const t3 = (await (await tokenReq(c2)).json()) as Record<string, string>;
	check((await tokenReq(c2)).status === 400, 'code replay rejected');
	check(
		(await fetch(`${issuer}/userinfo`, { headers: { authorization: `Bearer ${t3.access_token}` } }))
			.status === 401,
		'code replay revoked issued tokens',
	);

	// Explicit revocation.
	const c3 = (await grant()).searchParams.get('code')!;
	const t4 = (await (await tokenReq(c3)).json()) as Record<string, string>;
	check(
		(await post('/revoke', { token: t4.refresh_token!, client_id: 'demo' })).status === 200,
		'revoke 200',
	);
	check(
		(await fetch(`${issuer}/userinfo`, { headers: { authorization: `Bearer ${t4.access_token}` } }))
			.status === 401,
		'revoked access token rejected',
	);

	const cc = await post(
		'/token',
		{ grant_type: 'client_credentials', scope: 'profile' },
		{ authorization: `Basic ${btoa('svc:s3cret')}` },
	);
	check(
		cc.status === 200 && !('refresh_token' in ((await cc.json()) as object)),
		'client_credentials',
	);
	check((await fetch(`${issuer}/healthz`)).status === 200, 'healthz');
	log(`smoke passed in ${Math.round(performance.now() - t0)} ms`);
} catch (err) {
	log(String(err));
	process.exitCode = 1;
} finally {
	await server.stop(true);
}
