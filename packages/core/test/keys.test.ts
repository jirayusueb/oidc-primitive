import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import { AccessToken, Keys } from '../src/index.ts';

describe('RFC 7517 s5 JWK Set publishing', () => {
	it('publishes public members with kid, alg and use', async () => {
		const { publicKey } = await Keys.generate('ES256');
		const { keys } = await Keys.jwks([{ key: publicKey, kid: 'k1', alg: 'ES256' }]);
		assert.equal(keys.length, 1);
		assert.deepEqual([keys[0]?.kid, keys[0]?.alg, keys[0]?.use, keys[0]?.kty], ['k1', 'ES256', 'sig', 'EC']);
		assert.equal('d' in (keys[0] ?? {}), false);
	});

	it('generates non-extractable private keys by default', async () => {
		const { privateKey } = await Keys.generate('ES256');
		assert.equal(privateKey.extractable, false);
		await assert.rejects(exportJWK(privateKey));
	});

	it('throws when a private key or JWK would be published', async () => {
		const { privateKey } = await Keys.generate('ES256', { extractable: true });
		await assert.rejects(Keys.jwks([{ key: privateKey, kid: 'k', alg: 'ES256' }]), TypeError);
		const jwk = await exportJWK(privateKey);
		await assert.rejects(Keys.publicJwk(jwk, { kid: 'k', alg: 'ES256' }), TypeError);
		await assert.rejects(Keys.publicJwk({ kty: 'oct', k: 'AAAA' }, { kid: 'k', alg: 'HS256' }), TypeError);
	});
});

describe('RFC 7638 thumbprint', () => {
	it('matches the jose thumbprint', async () => {
		const { publicKey } = await Keys.generate('ES256');
		const jwk = await exportJWK(publicKey);
		assert.equal(await Keys.thumbprint(jwk), await calculateJwkThumbprint(jwk));
	});
});

describe('RFC 7517 s5 local JWK Set resolver', () => {
	it('verifies a token through the set and picks the key by kid', async () => {
		const a = await Keys.generate('ES256');
		const b = await Keys.generate('ES256');
		const keys = Keys.localResolver({
			keys: [await Keys.publicJwk(a.publicKey, { kid: 'a', alg: 'ES256' }), await Keys.publicJwk(b.publicKey, { kid: 'b', alg: 'ES256' })],
		});
		const options = { issuer: 'https://op.example', audience: 'https://rs.example', keys };
		const claims = { sub: 'u', aud: options.audience, client_id: 'c' };
		const signWith = (key: CryptoKey, kid: string): Promise<string> =>
			AccessToken.sign(claims, { issuer: options.issuer, key, kid, alg: 'ES256' });
		assert.equal((await AccessToken.verify(await signWith(b.privateKey, 'b'), options)).sub, 'u');
		await assert.rejects(AccessToken.verify(await signWith(b.privateKey, 'a'), options));
		await assert.rejects(AccessToken.verify(await signWith(b.privateKey, 'zzz'), options));
	});

	it('freezes the algorithm lists', () => {
		assert.deepEqual([...Keys.tokenAlgorithms], ['ES256', 'EdDSA', 'PS256', 'RS256']);
		assert.equal(Keys.assertionAlgorithms.length, 10);
		assert.equal('allowedAlgorithms' in Keys, false);
	});
});
