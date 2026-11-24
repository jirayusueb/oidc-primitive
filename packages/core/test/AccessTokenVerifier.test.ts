import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { SignJWT } from 'jose';
import * as AccessTokenVerifier from '../src/AccessTokenVerifier.ts';
import * as Keys from '../src/Keys.ts';
import { InvalidToken } from '../src/OAuthError.ts';
import * as Scope from '../src/Scope.ts';
import * as TokenSigner from '../src/TokenSigner.ts';

const issuer = 'https://op.example';
const audience = 'https://rs.example';
const { publicKey, privateKey } = await Keys.generate('ES256');
const signer = TokenSigner.make({ issuer, key: privateKey, kid: 'k1', alg: 'ES256' });
const read = Scope.make('read');
const admin = Scope.make('admin');
const verifier = AccessTokenVerifier.make({ issuer, audience, keys: publicKey, scopes: [read, admin] });
const issue = (scope?: string): Promise<string> =>
	signer.accessToken({ sub: 'u', aud: audience, client_id: 'c', scope });

describe('RFC 9068 s4 resource server verification', () => {
	it('filters undeclared scopes without rejecting', async () => {
		const v = await verifier.verify(await issue('read other'));
		const granted: Array<'read' | 'admin'> = v.granted;
		assert.deepEqual(granted, ['read']);
		assert.deepEqual(v.scope, ['read', 'other']);
		assert.equal(v.sub, 'u');
	});

	it('handles a token with no scope', async () => {
		const v = await verifier.verify(await issue());
		assert.deepEqual([v.granted, v.scope], [[], []]);
	});

	it('rejects an invalid token', async () => {
		await assert.rejects(verifier.verify('nope'), InvalidToken);
		const jwt = await new SignJWT({}).setProtectedHeader({ alg: 'ES256', typ: 'JWT' }).sign(privateKey);
		await assert.rejects(verifier.verify(jwt), InvalidToken);
	});
});

describe('RFC 6750 s2.1 verifyRequest', () => {
	it('reads the Authorization header only', async () => {
		const jwt = await issue('read');
		const v = await verifier.verifyRequest(new Headers({ Authorization: `Bearer ${jwt}` }));
		assert.deepEqual(v.granted, ['read']);
	});

	it('throws InvalidToken when missing, other scheme or malformed', async () => {
		for (const h of [{} as Record<string, string>, { Authorization: 'Basic Zm9v' }, { Authorization: 'Bearer a b' }]) {
			await assert.rejects(verifier.verifyRequest(new Headers(h)), InvalidToken);
		}
	});
});

describe('RFC 9449 s7.1 confirm passthrough', () => {
	it('rejects cnf tokens without confirm and accepts with it', async () => {
		const jwt = await signer.accessToken({ sub: 'u', aud: audience, client_id: 'c', cnf: { jkt: 'x' } });
		await assert.rejects(verifier.verify(jwt), InvalidToken);
		const bound = AccessTokenVerifier.make({ issuer, audience, keys: publicKey, confirm: () => {} });
		assert.deepEqual((await bound.verify(jwt)).cnf, { jkt: 'x' });
	});
});
