import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';
import { ClientAssertion, Keys, OAuthError } from '../src/index.ts';
const { InvalidClient, TemporarilyUnavailable } = OAuthError;

const issuer = 'https://as.example.com';
const clientId = 'client-1';
const { publicKey, privateKey } = await generateKeyPair('ES256');

const sign = (
	claims: Record<string, unknown>,
	exp: number | string = '5m',
	alg = 'ES256',
	key: CryptoKey | Uint8Array = privateKey,
) => {
	const jwt = new SignJWT({ jti: 'j1', iss: clientId, sub: clientId, aud: issuer, ...claims })
		.setProtectedHeader({ alg })
		.setIssuedAt();
	return (exp === '' ? jwt : jwt.setExpirationTime(exp)).sign(key);
};
const verify = (jwt: string) => ClientAssertion.verify(jwt, { issuer, clientId, keys: publicKey });
const rejects = (jwt: Promise<string>) =>
	jwt.then((value) => assert.rejects(verify(value), InvalidClient));

describe('RFC 7523 s3 and RFC 10070 s4 client assertion', () => {
	it('accepts a valid assertion and returns replay data', async () => {
		const result = await verify(await sign({}));
		assert.equal(result.jti, 'j1');
		assert.ok(result.expiresAt > Date.now() / 1000);
	});

	it('accepts aud as [issuer]', async () => {
		await verify(await sign({ aud: [issuer] }));
	});

	it('rejects the token endpoint URL as aud', () => rejects(sign({ aud: `${issuer}/token` })));
	it('rejects aud [issuer, other]', () =>
		rejects(sign({ aud: [issuer, 'https://other.example'] })));
	it('rejects iss mismatch', () => rejects(sign({ iss: 'other' })));
	it('rejects sub mismatch', () => rejects(sign({ sub: 'other' })));
	it('rejects exp too far ahead', () => rejects(sign({}, '1h')));
	it('rejects missing exp', () => rejects(sign({}, '')));
	it('rejects missing jti', () => rejects(sign({ jti: undefined })));

	it('rejects HS256 even with an oct key', async () => {
		const secret = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
		const jwt = await sign({}, '5m', 'HS256', secret);
		const key = await crypto.subtle.importKey(
			'raw',
			secret,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['verify'],
		);
		await assert.rejects(
			ClientAssertion.verify(jwt, { issuer, clientId, keys: key }),
			InvalidClient,
		);
	});

	it('rejects a wrong key and an expired assertion', async () => {
		const other = await generateKeyPair('ES256');
		const jwt = await sign({});
		await assert.rejects(
			ClientAssertion.verify(jwt, { issuer, clientId, keys: other.publicKey }),
			InvalidClient,
		);
		await assert.rejects(
			ClientAssertion.verify(jwt, {
				issuer,
				clientId,
				keys: publicKey,
				currentDate: new Date(Date.now() + 3_600_000),
			}),
			InvalidClient,
		);
	});

	it('uses the shared assertion algorithm list and the lowercase message', async () => {
		assert.equal('algorithms' in ClientAssertion, false);
		const error = await verify(await sign({ sub: 'other' })).catch((e: unknown) => e);
		assert.ok(error instanceof InvalidClient);
		assert.equal(error.description, 'client assertion is invalid');
		const rsa = await Keys.generate('RS384');
		const jwt = await sign({}, '5m', 'RS384', rsa.privateKey);
		assert.equal(
			(await ClientAssertion.verify(jwt, { issuer, clientId, keys: rsa.publicKey })).jti,
			'j1',
		);
	});

	it('verifies through a local JWK set', async () => {
		const keys = Keys.localResolver({
			keys: [await Keys.publicJwk(publicKey, { kid: 'k1', alg: 'ES256' })],
		});
		assert.equal(
			(await ClientAssertion.verify(await sign({}), { issuer, clientId, keys })).jti,
			'j1',
		);
	});

	it('answers a forged alg that mismatches the key with InvalidClient, never 503 (B1)', async () => {
		const rsa = await Keys.generate('RS256');
		await rejects(sign({}, '5m', 'RS256', rsa.privateKey));
	});

	it('answers an unreachable remote key set with TemporarilyUnavailable', async () => {
		const keys = Keys.remoteResolver('http://127.0.0.1:1/jwks', { timeoutDuration: 500 });
		await assert.rejects(
			ClientAssertion.verify(await sign({}), { issuer, clientId, keys }),
			TemporarilyUnavailable,
		);
	});

	it('exposes the assertion type', () => {
		assert.equal(
			ClientAssertion.assertionType,
			'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
		);
	});
});

describe('RFC 7519 s4.1.7 jti', () => {
	it('rejects a non-string or empty jti', async () => {
		for (const jti of [5, { a: 1 }, ['x'], true, '']) {
			await rejects(sign({ jti } as never));
		}
	});
});

describe('RFC 8725 s3.1 assertion algorithms', () => {
	it('rejects an unsigned alg none assertion', async () => {
		const b64 = (value: string): string =>
			btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		const now = Math.floor(Date.now() / 1000);
		const payload = {
			jti: 'j1',
			iss: clientId,
			sub: clientId,
			aud: issuer,
			iat: now,
			exp: now + 60,
		};
		const jwt = `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify(payload))}.`;
		await assert.rejects(verify(jwt), InvalidClient);
	});
});
