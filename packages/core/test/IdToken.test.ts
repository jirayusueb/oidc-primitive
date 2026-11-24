import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { base64url, decodeJwt, SignJWT } from 'jose';
import * as IdToken from '../src/IdToken.ts';
import * as Keys from '../src/Keys.ts';
import { InvalidRequest } from '../src/OAuthError.ts';
import * as Redacted from '../src/Redacted.ts';

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
		assert.equal(await IdToken.atHash(accessToken, 'ES256'), await independentAtHash(accessToken, 'SHA-256'));
	});

	it('matches the alg hash size', async () => {
		assert.equal(await IdToken.atHash('t', 'PS384'), await independentAtHash('t', 'SHA-384'));
		assert.equal(await IdToken.atHash('t', 'ES512'), await independentAtHash('t', 'SHA-512'));
		assert.equal(await IdToken.atHash('t', 'EdDSA'), await independentAtHash('t', 'SHA-512'));
		await assert.rejects(IdToken.atHash('t', 'HS256'), TypeError);
	});

	it('is set when accessToken is given, including Redacted', async () => {
		const jwt = await IdToken.sign({ sub: 'u', aud: 'c' }, { ...base, accessToken: Redacted.make('at-1') });
		assert.equal(decodeJwt(jwt).at_hash, await independentAtHash('at-1', 'SHA-256'));
		assert.equal(decodeJwt(await IdToken.sign({ sub: 'u', aud: 'c' }, base)).at_hash, undefined);
	});
});

describe('OIDC Core s2 azp and claims', () => {
	it('requires clientId for several audiences and sets azp', async () => {
		await assert.rejects(IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, base), TypeError);
		const claims = decodeJwt(await IdToken.sign({ sub: 'u', aud: ['a', 'b'] }, { ...base, clientId: 'a' }));
		assert.equal(claims.azp, 'a');
		assert.equal(decodeJwt(await IdToken.sign({ sub: 'u', aud: 'a' }, { ...base, clientId: 'a' })).azp, undefined);
	});

	it('sets iss, iat, exp and passes custom claims through', async () => {
		const c = decodeJwt(await IdToken.sign({ sub: 'u', aud: 'a', nonce: 'n', auth_time: 5, custom: 1 }, base));
		assert.equal(c.iss, issuer);
		assert.equal((c.exp as number) - (c.iat as number), 600);
		assert.deepEqual([c.nonce, c.auth_time, c.custom], ['n', 5, 1]);
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
		await assert.rejects(IdToken.verify(jwt, { ...options, keys: new Uint8Array(32) }), InvalidRequest);
	});
});
