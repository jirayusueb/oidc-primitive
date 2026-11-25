import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { AccessToken, Keys, TokenSigner } from '../src/index.ts';

const { publicKey, privateKey } = await Keys.generate('ES256');
const signer = TokenSigner.make({
	issuer: 'https://op.example',
	key: privateKey,
	kid: 'k1',
	alg: 'ES256',
});

describe('RFC 9068 and OIDC Core token signing with a bound key', () => {
	it('signs an access token verifiable with the public key', async () => {
		const jwt = await signer.signAccessToken(
			{ sub: 'u', aud: 'https://rs', client_id: 'c' },
			{ expiresIn: '1m' },
		);
		assert.equal(decodeProtectedHeader(jwt).typ, 'at+jwt');
		const v = await AccessToken.verify(jwt, {
			issuer: 'https://op.example',
			audience: 'https://rs',
			keys: publicKey,
		});
		assert.ok([60, 61].includes(v.exp - v.iat)); // a time span string is read by jose against its own clock
	});

	it('takes clientId and accessToken per call, so one signer serves every client', async () => {
		const jwt = await signer.signIdToken(
			{ sub: 'u', aud: ['c', 'd'] },
			{ clientId: 'c', accessToken: 'at' },
		);
		const c = decodeJwt(jwt);
		assert.equal(c.azp, 'c');
		assert.ok(c.at_hash);
		assert.equal(decodeProtectedHeader(jwt).kid, 'k1');
	});
});
