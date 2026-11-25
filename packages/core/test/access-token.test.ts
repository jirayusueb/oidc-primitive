import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { decodeJwt, decodeProtectedHeader, errors, SignJWT } from 'jose';
import { AccessToken, Keys, OAuthError } from '../src/index.ts';
const { InvalidToken, TemporarilyUnavailable } = OAuthError;

const issuer = 'https://op.example';
const audience = 'https://rs.example';
const { publicKey, privateKey } = await Keys.generate('ES256');
const base = { issuer, key: privateKey, kid: 'k1', alg: 'ES256' };
const claims = { sub: 'u', aud: audience, client_id: 'c', scope: 'read write' };
const options = { issuer, audience, keys: publicKey };

const raw = (
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
	key: CryptoKey | Uint8Array = privateKey,
): Promise<string> => new SignJWT(payload).setProtectedHeader(header as { alg: string }).sign(key);

const now = (): number => Math.floor(Date.now() / 1000);
const full = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
	iss: issuer,
	aud: audience,
	sub: 'u',
	client_id: 'c',
	jti: 'j',
	iat: now() - 10,
	exp: now() + 600,
	...over,
});

describe('RFC 9068 s2 signing', () => {
	it('sets typ, jti, iss, iat, exp', async () => {
		const jwt = await AccessToken.sign(claims, base);
		const header = decodeProtectedHeader(jwt);
		assert.deepEqual([header.typ, header.alg, header.kid], ['at+jwt', 'ES256', 'k1']);
		const c = decodeJwt(jwt);
		assert.equal(c.iss, issuer);
		assert.ok(c.jti);
		assert.equal((c.exp as number) - (c.iat as number), AccessToken.defaultLifetime);
		assert.notEqual(c.jti, decodeJwt(await AccessToken.sign(claims, base)).jti);
	});

	it('round-trips through verify', async () => {
		const v = await AccessToken.verify(await AccessToken.sign(claims, base), options);
		assert.deepEqual([v.sub, v.client_id, v.scope], ['u', 'c', 'read write']);
	});
});

describe('RFC 9068 s2 expiresIn', () => {
	it('reads a number as seconds from now and defaults to 600', async () => {
		assert.equal(AccessToken.defaultLifetime, 600);
		const c = decodeJwt(await AccessToken.sign(claims, { ...base, expiresIn: 120 }));
		assert.equal((c.exp as number) - (c.iat as number), 120);
		assert.ok(Math.abs((c.exp as number) - (now() + 120)) <= 1);
	});
});

describe('RFC 8725 s3.1 key failures (B1)', () => {
	const header = { alg: 'ES256', typ: 'at+jwt' };

	it('answers a forged header that mismatches the key with InvalidToken, never 503', async () => {
		const rsa = await Keys.generate('RS256');
		const jwt = await raw({ alg: 'RS256', typ: 'at+jwt' }, full(), rsa.privateKey);
		await assert.rejects(AccessToken.verify(jwt, options), InvalidToken);
		await assert.rejects(
			AccessToken.verify(jwt, {
				...options,
				keys: await Keys.publicJwk(publicKey, { kid: 'k', alg: 'ES256' }),
			}),
			InvalidToken,
		);
	});

	it('answers an unreachable remote key set with TemporarilyUnavailable', async () => {
		const keys = Keys.remoteResolver('http://127.0.0.1:1/jwks', { timeoutDuration: 500 });
		await assert.rejects(
			AccessToken.verify(await raw(header, full()), { ...options, keys }),
			TemporarilyUnavailable,
		);
	});

	it('keeps an unknown kid in a local set at InvalidToken', async () => {
		const keys = Keys.localResolver({
			keys: [await Keys.publicJwk(publicKey, { kid: 'k1', alg: 'ES256' })],
		});
		const jwt = await raw({ ...header, kid: 'other' }, full());
		await assert.rejects(AccessToken.verify(jwt, { ...options, keys }), InvalidToken);
	});
});

describe('RFC 9068 s4 verification (D9)', () => {
	it('rejects typ other than at+jwt, or missing', async () => {
		await assert.rejects(
			AccessToken.verify(await raw({ alg: 'ES256', typ: 'JWT' }, full()), options),
			InvalidToken,
		);
		await assert.rejects(
			AccessToken.verify(await raw({ alg: 'ES256' }, full()), options),
			InvalidToken,
		);
	});

	it('rejects algorithms outside the allow-list', async () => {
		const secret = new Uint8Array(32);
		const jwt = await raw({ alg: 'HS256', typ: 'at+jwt' }, full(), secret);
		// A raw secret is outside VerifyKey; force it through to prove the runtime allow-list still rejects HS256.
		await assert.rejects(
			AccessToken.verify(jwt, { ...options, keys: secret as never }),
			InvalidToken,
		);
		await assert.rejects(AccessToken.verify(jwt, { ...options, algorithms: ['HS256'] }), TypeError);
	});

	it('rejects wrong issuer, audience, signature and missing claims', async () => {
		const header = { alg: 'ES256', typ: 'at+jwt' };
		for (const jwt of [
			await raw(header, full({ iss: 'https://evil' })),
			await raw(header, full({ aud: 'https://other' })),
			await raw(header, full({ jti: undefined })),
			await raw(header, full({ client_id: undefined })),
			await raw(header, full(), (await Keys.generate('ES256')).privateKey),
		]) {
			await assert.rejects(AccessToken.verify(jwt, options), InvalidToken);
		}
	});

	it('applies a 30 s clock tolerance to exp and nbf', async () => {
		const header = { alg: 'ES256', typ: 'at+jwt' };
		await AccessToken.verify(await raw(header, full({ exp: now() - 20 })), options);
		await assert.rejects(
			AccessToken.verify(await raw(header, full({ exp: now() - 60 })), options),
			InvalidToken,
		);
		await assert.rejects(
			AccessToken.verify(await raw(header, full({ nbf: now() + 120 })), options),
			InvalidToken,
		);
		await assert.rejects(
			AccessToken.verify(await raw(header, full({ exp: now() - 20 })), {
				...options,
				clockTolerance: 5,
			}),
			InvalidToken,
		);
	});

	it('does not echo the token in the error', async () => {
		const jwt = await raw({ alg: 'ES256' }, full());
		const error = await AccessToken.verify(jwt, options).catch((e: Error) => e);
		assert.ok(error instanceof InvalidToken);
		assert.equal(String(error.message).includes(jwt), false);
	});
});

describe('RFC 9449 s7.1 cnf', () => {
	const header = { alg: 'ES256', typ: 'at+jwt' };

	it('rejects a bound token without confirm', async () => {
		await assert.rejects(
			AccessToken.verify(await raw(header, full({ cnf: { jkt: 'x' } })), options),
			InvalidToken,
		);
	});

	it('accepts when confirm passes, rejects when it throws', async () => {
		const jwt = await raw(header, full({ cnf: { jkt: 'x' } }));
		let seen: unknown;
		const v = await AccessToken.verify(jwt, {
			...options,
			confirm: async (cnf) => void (seen = cnf),
		});
		assert.deepEqual(seen, { jkt: 'x' });
		assert.deepEqual(v.cnf, { jkt: 'x' });
		await assert.rejects(
			AccessToken.verify(jwt, {
				...options,
				confirm: () => {
					throw new Error('mismatch');
				},
			}),
			InvalidToken,
		);
	});
});

describe('RFC 7519 s4.1.2, s4.1.7 and RFC 7800 s3.1 claim types', () => {
	it('rejects non-string sub or jti', async () => {
		await assert.rejects(
			AccessToken.verify(await raw({ alg: 'ES256', typ: 'at+jwt' }, full({ sub: 5 })), options),
			InvalidToken,
		);
		await assert.rejects(
			AccessToken.verify(await raw({ alg: 'ES256', typ: 'at+jwt' }, full({ jti: 7 })), options),
			InvalidToken,
		);
	});

	it('rejects an array cnf even with confirm', async () => {
		await assert.rejects(
			AccessToken.verify(await raw({ alg: 'ES256', typ: 'at+jwt' }, full({ cnf: ['x'] })), {
				...options,
				confirm: () => {},
			}),
			InvalidToken,
		);
	});

	it('rejects an unsigned alg none token (design D9)', async () => {
		const b64 = (value: string): string =>
			btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		const jwt = `${b64(JSON.stringify({ alg: 'none', typ: 'at+jwt' }))}.${b64(JSON.stringify(full()))}.`;
		await assert.rejects(AccessToken.verify(jwt, options), InvalidToken);
	});
});

describe('RFC 9068 s4 key resolution failures answer 503 (design D9)', () => {
	it('answers 503 when the remote key set cannot be fetched', async () => {
		const keys = Keys.remoteResolver('http://127.0.0.1:9/jwks', { timeoutDuration: 500 });
		const jwt = await AccessToken.sign(claims, base);
		await assert.rejects(
			AccessToken.verify(jwt, { issuer, audience, keys }),
			TemporarilyUnavailable,
		);
	});

	it('answers 503 when the key server returns an invalid JWK Set', async () => {
		const keys = async (): Promise<never> => {
			throw new errors.JWKSInvalid('JSON Web Key Set malformed');
		};
		const jwt = await AccessToken.sign(claims, base);
		await assert.rejects(
			AccessToken.verify(jwt, { issuer, audience, keys }),
			TemporarilyUnavailable,
		);
	});
});
