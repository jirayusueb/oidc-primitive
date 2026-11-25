// Compile-time checks; `bun run type-check` fails when a type drifts (design G4).
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import {
	AccessToken,
	AccessTokenVerifier,
	IdToken,
	Keys,
	Scope,
	TokenSigner,
} from '../src/index.ts';

type Equal<A, B> =
	(<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
const expectType = <T extends true>(): T => true as T;

type Bound = keyof TokenSigner.Options;

// Class methods take the function's arguments minus the bound options.
expectType<
	Equal<
		Parameters<TokenSigner.TokenSigner['signIdToken']>[1],
		Omit<IdToken.SignOptions, Bound> | undefined
	>
>();
expectType<
	Equal<
		Parameters<TokenSigner.TokenSigner['signAccessToken']>[1],
		Omit<AccessToken.SignOptions, Bound> | undefined
	>
>();
expectType<Equal<Parameters<TokenSigner.TokenSigner['signIdToken']>[0], IdToken.Claims>>();

describe('RFC 6749 s3.3 scope literals flow into verifier results (design D5)', () => {
	it('types granted scopes by the declaration', async () => {
		const { publicKey } = await Keys.generate('ES256');
		const verifier = AccessTokenVerifier.make({
			issuer: 'https://op.example',
			audience: 'https://rs.example',
			keys: publicKey,
			scopes: [Scope.make('read'), Scope.make('write')],
		});
		type Granted = Awaited<ReturnType<typeof verifier.verify>>['granted'][number];
		expectType<Equal<Granted, Scope.Scope<'read'> | Scope.Scope<'write'>>>();
		assert.ok(verifier instanceof AccessTokenVerifier.AccessTokenVerifier);
	});
});
