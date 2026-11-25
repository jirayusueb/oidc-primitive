import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { SignJWT } from 'jose';
import { AccessTokenVerifier, Keys, OAuthError, Scope, TokenSigner } from '../src/index.ts';
const { InvalidToken } = OAuthError;

const issuer = 'https://op.example';
const audience = 'https://rs.example';
const { publicKey, privateKey } = await Keys.generate('ES256');
const signer = TokenSigner.make({ issuer, key: privateKey, kid: 'k1', alg: 'ES256' });
const read = Scope.make('read');
const admin = Scope.make('admin');
const verifier = AccessTokenVerifier.make({
	issuer,
	audience,
	keys: publicKey,
	scopes: [read, admin],
});
const issue = (scope?: string): Promise<string> =>
	signer.signAccessToken({ sub: 'u', aud: audience, client_id: 'c', scope });

describe('RFC 9068 s4 resource server verification', () => {
	it('filters undeclared scopes without rejecting', async () => {
		const v = await verifier.verify(await issue('read other'));
		const granted: Array<'read' | 'admin'> = v.granted;
		assert.deepEqual(granted, ['read']);
		assert.deepEqual(v.scope, ['read', 'other']);
		assert.equal(v.claims.sub, 'u');
	});

	it('handles a token with no scope', async () => {
		const v = await verifier.verify(await issue());
		assert.deepEqual([v.granted, v.scope], [[], []]);
	});

	it('rejects an invalid token', async () => {
		await assert.rejects(verifier.verify('nope'), InvalidToken);
		const jwt = await new SignJWT({})
			.setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
			.sign(privateKey);
		await assert.rejects(verifier.verify(jwt), InvalidToken);
	});
});

describe('RFC 6750 s2.1 verifyHeaders', () => {
	it('reads the Authorization header only', async () => {
		const jwt = await issue('read');
		const v = await verifier.verifyHeaders(new Headers({ Authorization: `Bearer ${jwt}` }));
		assert.deepEqual(v.granted, ['read']);
	});

	it('answers a missing or other-scheme credential with a bare Bearer challenge (RFC 6750 s3.1)', async () => {
		for (const h of [{} as Record<string, string>, { Authorization: 'Basic Zm9v' }]) {
			const error = await verifier.verifyHeaders(new Headers(h)).catch((e: unknown) => e);
			assert.ok(error instanceof OAuthError.MissingToken);
			const res = error.toResponse();
			assert.equal(res.status, 401);
			assert.equal(res.headers.get('www-authenticate'), 'Bearer');
		}
	});

	it('throws InvalidToken for a malformed Bearer credential', async () => {
		await assert.rejects(
			verifier.verifyHeaders(new Headers({ Authorization: 'Bearer a b' })),
			InvalidToken,
		);
	});
});

describe('RFC 9449 s7.1 confirm passthrough', () => {
	it('rejects cnf tokens without confirm and accepts with it', async () => {
		const jwt = await signer.signAccessToken({
			sub: 'u',
			aud: audience,
			client_id: 'c',
			cnf: { jkt: 'x' },
		});
		await assert.rejects(verifier.verify(jwt), InvalidToken);
		const bound = AccessTokenVerifier.make({
			issuer,
			audience,
			keys: publicKey,
			confirm: () => {},
		});
		assert.deepEqual((await bound.verify(jwt)).claims.cnf, { jkt: 'x' });
	});
});
