// Regressions for code review round 1 (CodeReview1, 2026-11-24).
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { inspect } from 'node:util';
import { SignJWT } from 'jose';
import { AccessToken, ClientAssertion, IdToken, Keys, Metadata, OAuthError, Pkce, ResourceMetadata } from '../src/index.ts';

const issuer = 'https://as.example';
const { publicKey, privateKey } = await Keys.generate('ES256');
const now = (): number => Math.floor(Date.now() / 1000);

describe('RFC 8414 s3.1 and RFC 9728 s3.1 well-known URLs', () => {
	it('drops a terminating slash from the issuer path', () => {
		assert.equal(
			Metadata.wellKnownUrls('https://as.example/tenant/').oauthAuthorizationServer,
			'https://as.example/.well-known/oauth-authorization-server/tenant',
		);
	});

	it('keeps the resource query and drops a terminating slash', () => {
		assert.equal(
			ResourceMetadata.wellKnownUrl('https://api.example/v1/?x=1'),
			'https://api.example/.well-known/oauth-protected-resource/v1?x=1',
		);
	});

	it('lists RS256 for ID tokens by default (OIDC Discovery s3)', () => {
		const doc = Metadata.authorizationServer({
			issuer,
			endpoints: { authorization: `${issuer}/authorize`, token: `${issuer}/token`, jwks: `${issuer}/jwks` },
		});
		assert.deepEqual(doc.id_token_signing_alg_values_supported, ['RS256']);
	});
});

describe('OIDC Core s2 azp', () => {
	it('refuses a clientId that is not in aud', async () => {
		await assert.rejects(
			IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, { issuer, key: privateKey, kid: 'k', alg: 'ES256', clientId: 'z' }),
			TypeError,
		);
	});
});

describe('RFC 7519 string claims', () => {
	const at = (claims: Record<string, unknown>) =>
		new SignJWT({ aud: 'https://rs', client_id: 'c', sub: 'u', jti: 'j', ...claims })
			.setProtectedHeader({ alg: 'ES256', typ: 'at+jwt' })
			.setIssuer(issuer)
			.setIssuedAt()
			.setExpirationTime('5m')
			.sign(privateKey);
	const options = { issuer, audience: 'https://rs', keys: publicKey };

	it('rejects non-string sub or jti in access tokens', async () => {
		await assert.rejects(AccessToken.verify(await at({ sub: 5 }), options), OAuthError.InvalidToken);
		await assert.rejects(AccessToken.verify(await at({ jti: 7 }), options), OAuthError.InvalidToken);
	});

	it('rejects an array cnf even with confirm (RFC 7800 s3.1)', async () => {
		await assert.rejects(
			AccessToken.verify(await at({ cnf: ['x'] }), { ...options, confirm: () => {} }),
			OAuthError.InvalidToken,
		);
	});

	it('rejects a non-string jti in client assertions', async () => {
		for (const jti of [5, { a: 1 }, ['x'], true, '']) {
			const jwt = await new SignJWT({ jti } as never)
				.setProtectedHeader({ alg: 'ES256' })
				.setIssuer('c')
				.setSubject('c')
				.setAudience(issuer)
				.setExpirationTime(now() + 60)
				.sign(privateKey);
			await assert.rejects(ClientAssertion.verify(jwt, { issuer, clientId: 'c', keys: publicKey }), OAuthError.InvalidClient);
		}
	});
});

describe('key fetch failures are not bad credentials', () => {
	it('answers 503 when the remote key set cannot be fetched', async () => {
		const keys = Keys.remoteSet('http://127.0.0.1:9/jwks', { timeoutDuration: 500 });
		const jwt = await AccessToken.sign({ sub: 'u', aud: 'https://rs', client_id: 'c' }, { issuer, key: privateKey, kid: 'k', alg: 'ES256' });
		await assert.rejects(AccessToken.verify(jwt, { issuer, audience: 'https://rs', keys }), OAuthError.TemporarilyUnavailable);
	});
});

describe('async and response safety', () => {
	it('rejects a malformed verifier asynchronously', async () => {
		const pending = Pkce.challenge('short');
		assert.ok(pending instanceof Promise);
		await assert.rejects(pending, OAuthError.InvalidRequest);
	});

	it('drops an unsafe description from the Bearer challenge instead of throwing', () => {
		const res = new OAuthError.InvalidToken('café "x"').toResponse();
		assert.equal(res.status, 401);
		assert.equal(res.headers.get('www-authenticate'), 'Bearer error="invalid_token"');
	});
});

describe('G5 errors carry no secret input', () => {
	it('never echoes the credential a primitive rejected', async () => {
		const secret = 's3cr3tTokenValue0123456789abcdefghijklmnopq';
		const rejected: unknown[] = await Promise.all([
			AccessToken.verify(secret, { issuer, audience: 'https://rs', keys: publicKey }).catch((e: unknown) => e),
			ClientAssertion.verify(secret, { issuer, clientId: 'c', keys: publicKey }).catch((e: unknown) => e),
			IdToken.verify(secret, { issuer, audience: 'c', keys: publicKey }).catch((e: unknown) => e),
			Pkce.verify(secret, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM').catch((e: unknown) => e),
		]);
		for (const error of rejected) {
			assert.ok(error instanceof OAuthError.OAuthError);
			const body = await error.toResponse().text();
			for (const out of [String(error), `${error}`, JSON.stringify(error), inspect(error), body]) {
				assert.equal(out.includes(secret), false, out);
			}
		}
	});
});
