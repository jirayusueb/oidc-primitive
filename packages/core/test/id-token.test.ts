import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { base64url, decodeJwt, SignJWT } from 'jose';
import { IdToken, Keys, OAuthError, Redacted } from '../src/index.ts';
const { InvalidRequest } = OAuthError;

const issuer = 'https://op.example';
const { publicKey, privateKey } = await Keys.generate('ES256');
const base = { issuer, key: privateKey, kid: 'k1', alg: 'ES256' };

const independentAtHash = async (value: string, name: string): Promise<string> => {
	const digest = new Uint8Array(await crypto.subtle.digest(name, new TextEncoder().encode(value)));
	return base64url.encode(digest.slice(0, digest.length / 2));
};

describe('OIDC Core s3.1.3.6 at_hash', () => {
	it('is the base64url left half of SHA-256 for ES256', async () => {
		const accessToken = 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y';
		// OIDC Core Appendix A.3 vector.
		assert.equal(await IdToken.atHash(accessToken, 'RS256'), '77QmUPtjPfzWtF2AnpK9RQ');
		assert.equal(
			await IdToken.atHash(accessToken, 'ES256'),
			await independentAtHash(accessToken, 'SHA-256'),
		);
	});

	it('matches the alg hash size', async () => {
		assert.equal(await IdToken.atHash('t', 'PS384'), await independentAtHash('t', 'SHA-384'));
		assert.equal(await IdToken.atHash('t', 'ES512'), await independentAtHash('t', 'SHA-512'));
		assert.equal(await IdToken.atHash('t', 'EdDSA'), await independentAtHash('t', 'SHA-512'));
		await assert.rejects(IdToken.atHash('t', 'HS256'), TypeError);
	});

	it('is set when accessToken is given, including Redacted', async () => {
		const jwt = await IdToken.sign(
			{ sub: 'u', aud: 'c' },
			{ ...base, accessToken: Redacted.make('at-1') },
		);
		assert.equal(decodeJwt(jwt).at_hash, await independentAtHash('at-1', 'SHA-256'));
		assert.equal(decodeJwt(await IdToken.sign({ sub: 'u', aud: 'c' }, base)).at_hash, undefined);
	});
});

describe('OIDC Core s2 azp and claims', () => {
	it('requires clientId for several audiences and sets azp', async () => {
		await assert.rejects(IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, base), TypeError);
		const claims = decodeJwt(
			await IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, { ...base, clientId: 'a' }),
		);
		assert.equal(claims.azp, 'a');
		assert.equal(
			decodeJwt(await IdToken.sign({ sub: 'u', aud: 'a' }, { ...base, clientId: 'a' })).azp,
			undefined,
		);
	});

	it('sets iss, iat, exp and passes custom claims through', async () => {
		const c = decodeJwt(
			await IdToken.sign({ sub: 'u', aud: 'a', nonce: 'n', auth_time: 5, custom: 1 }, base),
		);
		assert.equal(c.iss, issuer);
		assert.equal((c.exp as number) - (c.iat as number), IdToken.defaultLifetime);
		assert.equal(IdToken.defaultLifetime, 600);
		assert.deepEqual([c.nonce, c.auth_time, c.custom], ['n', 5, 1]);
	});
});

describe('OIDC Core s3.1.3.7 expiresIn', () => {
	it('reads a number as seconds from now', async () => {
		const c = decodeJwt(await IdToken.sign({ sub: 'u', aud: 'a' }, { ...base, expiresIn: 90 }));
		assert.equal((c.exp as number) - (c.iat as number), 90);
	});
});

describe('OIDC Core s3.1.2.1 id_token_hint', () => {
	const options = { issuer, audience: 'c', keys: publicKey };

	it('verifies a valid token', async () => {
		const jwt = await IdToken.sign({ sub: 'u', aud: 'c' }, base);
		assert.equal((await IdToken.verify(jwt, options)).sub, 'u');
	});

	const expired = async (): Promise<string> =>
		new SignJWT({ sub: 'u' })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(issuer)
			.setAudience('c')
			.setIssuedAt(1000)
			.setExpirationTime(2000)
			.sign(privateKey);

	it('returns typed claims and rejects a non-string sub', async () => {
		const claims = await IdToken.verify(await IdToken.sign({ sub: 'u', aud: 'c' }, base), options);
		const typed: [string, string, string | string[], number, number] = [
			claims.iss,
			claims.sub,
			claims.aud,
			claims.iat,
			claims.exp,
		];
		assert.equal(typed[0], issuer);
		const jwt = await new SignJWT({ sub: 5 as unknown as string })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(issuer)
			.setAudience('c')
			.setIssuedAt()
			.setExpirationTime('10m')
			.sign(privateKey);
		await assert.rejects(IdToken.verify(jwt, options), InvalidRequest);
	});

	it('applies a 30 s clock tolerance, configurable', async () => {
		const near = await new SignJWT({ sub: 'u' })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(issuer)
			.setAudience('c')
			.setIssuedAt(Math.floor(Date.now() / 1000) - 600)
			.setExpirationTime(Math.floor(Date.now() / 1000) - 20)
			.sign(privateKey);
		assert.equal((await IdToken.verify(near, options)).sub, 'u');
		await assert.rejects(IdToken.verify(near, { ...options, clockTolerance: 5 }), InvalidRequest);
	});

	it('answers a key that mismatches the header alg with InvalidRequest', async () => {
		const rsa = await Keys.generate('RS256');
		const jwt = await new SignJWT({ sub: 'u' })
			.setProtectedHeader({ alg: 'RS256' })
			.setIssuer(issuer)
			.setAudience('c')
			.setIssuedAt()
			.setExpirationTime('10m')
			.sign(rsa.privateKey);
		await assert.rejects(IdToken.verify(jwt, options), InvalidRequest);
	});

	it('rejects an expired token unless allowExpired', async () => {
		const jwt = await expired();
		await assert.rejects(IdToken.verify(jwt, options), InvalidRequest);
		assert.equal((await IdToken.verify(jwt, { ...options, allowExpired: true })).sub, 'u');
	});

	it('still checks signature, issuer and audience with allowExpired', async () => {
		const jwt = await expired();
		const other = await Keys.generate('ES256');
		const allow = { ...options, allowExpired: true };
		await assert.rejects(IdToken.verify(jwt, { ...allow, keys: other.publicKey }), InvalidRequest);
		await assert.rejects(IdToken.verify(jwt, { ...allow, audience: 'x' }), InvalidRequest);
		await assert.rejects(IdToken.verify(jwt, { ...allow, issuer: 'https://evil' }), InvalidRequest);
	});

	it('rejects HS256', async () => {
		const jwt = await new SignJWT({ sub: 'u' })
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuer(issuer)
			.setAudience('c')
			.setIssuedAt()
			.setExpirationTime('10m')
			.sign(new Uint8Array(32));
		await assert.rejects(
			IdToken.verify(jwt, { ...options, keys: new Uint8Array(32) as never }),
			InvalidRequest,
		);
	});
});

describe('OIDC Core s2 azp', () => {
	it('refuses a clientId that is not in aud', async () => {
		await assert.rejects(
			IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, { ...base, clientId: 'z' }),
			TypeError,
		);
	});
});

describe('RFC 8725 s3.1 and RFC 7518 s3.6 algorithm allow-list (design D9)', () => {
	it('rejects an unsigned alg none token', async () => {
		const b64 = (value: string): string =>
			btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		const payload = {
			sub: 'u',
			iss: issuer,
			aud: 'c',
			iat: Math.floor(Date.now() / 1000) - 10,
			exp: Math.floor(Date.now() / 1000) + 600,
		};
		const jwt = `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify(payload))}.`;
		await assert.rejects(
			IdToken.verify(jwt, { issuer, audience: 'c', keys: publicKey }),
			InvalidRequest,
		);
	});
});
