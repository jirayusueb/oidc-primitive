import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SignJWT, generateKeyPair } from 'jose';
import { ClientAssertion, OAuthError } from '../src/index.ts';
const { InvalidClient } = OAuthError;

const issuer = 'https://as.example.com';
const clientId = 'client-1';
const { publicKey, privateKey } = await generateKeyPair('ES256');

const sign = (claims: Record<string, unknown>, exp: number | string = '5m', alg = 'ES256', key: CryptoKey | Uint8Array = privateKey) => {
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
	it('rejects aud [issuer, other]', () => rejects(sign({ aud: [issuer, 'https://other.example'] })));
	it('rejects iss mismatch', () => rejects(sign({ iss: 'other' })));
	it('rejects sub mismatch', () => rejects(sign({ sub: 'other' })));
	it('rejects exp too far ahead', () => rejects(sign({}, '1h')));
	it('rejects missing exp', () => rejects(sign({}, '')));
	it('rejects missing jti', () => rejects(sign({ jti: undefined })));

	it('rejects HS256 even with an oct key', async () => {
		const secret = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
		const jwt = await sign({}, '5m', 'HS256', secret);
		const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
		await assert.rejects(ClientAssertion.verify(jwt, { issuer, clientId, keys: key }), InvalidClient);
	});

	it('rejects a wrong key and an expired assertion', async () => {
		const other = await generateKeyPair('ES256');
		const jwt = await sign({});
		await assert.rejects(ClientAssertion.verify(jwt, { issuer, clientId, keys: other.publicKey }), InvalidClient);
		await assert.rejects(
			ClientAssertion.verify(jwt, { issuer, clientId, keys: publicKey, currentDate: new Date(Date.now() + 3_600_000) }),
			InvalidClient,
		);
	});

	it('exposes the assertion type', () => {
		assert.equal(ClientAssertion.assertionType, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
	});
});
