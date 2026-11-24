import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { OAuthError, Pkce } from '../src/index.ts';

// RFC 7636 Appendix B.
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('RFC 7636 s4.2 S256 challenge', () => {
	it('matches the Appendix B vector', async () => {
		assert.equal(await Pkce.challenge(verifier), challenge);
	});

	it('accepts the matching verifier', async () => {
		await Pkce.verify(verifier, challenge);
	});

	it('rejects a different verifier', async () => {
		await assert.rejects(Pkce.verify(`${verifier}x`, challenge), OAuthError.InvalidGrant);
	});
});

describe('RFC 7636 s4.1 verifier syntax', () => {
	it('rejects verifiers shorter than 43 or with reserved characters', async () => {
		assert.equal(Pkce.isVerifier('a'.repeat(42)), false);
		assert.equal(Pkce.isVerifier(`${'a'.repeat(42)}+`), false);
		assert.equal(Pkce.isVerifier('a'.repeat(128)), true);
		assert.equal(Pkce.isVerifier('a'.repeat(129)), false);
		await assert.rejects(Pkce.verify('short', challenge), OAuthError.InvalidGrant);
	});
});

describe('RFC 9700 s2.1.1 S256 only', () => {
	it('rejects plain and a missing method', () => {
		assert.throws(() => Pkce.checkMethod('plain'), OAuthError.InvalidRequest);
		assert.throws(() => Pkce.checkMethod(undefined), OAuthError.InvalidRequest);
		Pkce.checkMethod('S256');
	});
});

describe('RFC 9700 s4.8.2 downgrade', () => {
	it('rejects a verifier when no challenge was stored', async () => {
		await assert.rejects(Pkce.verify(verifier, undefined, { required: false }), OAuthError.InvalidGrant);
	});

	it('rejects a missing verifier when a challenge was stored', async () => {
		await assert.rejects(Pkce.verify(undefined, challenge, { required: false }), OAuthError.InvalidGrant);
	});

	it('requires PKCE unless the host exempts the client', async () => {
		await assert.rejects(Pkce.verify(undefined, undefined), OAuthError.InvalidGrant);
		await Pkce.verify(undefined, undefined, { required: false });
	});
});
