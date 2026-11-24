import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import { Keys } from '../src/index.ts';

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
