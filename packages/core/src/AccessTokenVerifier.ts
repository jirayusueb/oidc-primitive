import * as AccessToken from './AccessToken.ts';
import * as Bearer from './Bearer.ts';
import { InvalidToken } from './OAuthError.ts';
import * as Scope from './Scope.ts';
import type { VerifyKey } from './Keys.ts';

export interface Options<S extends string = string> {
	readonly issuer: string;
	readonly audience: string;
	readonly keys: VerifyKey;
	/** Scopes this resource server knows; others in a token are ignored, not rejected. */
	readonly scopes?: readonly S[];
	readonly clockTolerance?: number;
	readonly confirm?: AccessToken.VerifyOptions['confirm'];
}

export interface Verified<S extends string = string> extends Omit<AccessToken.VerifiedClaims, 'scope'> {
	/** Declared scopes present in the token. */
	readonly granted: S[];
	/** Every scope in the token. */
	readonly scope: string[];
}

/** AccessToken.verify bound to a resource server's issuer, audience and keys. */
export class AccessTokenVerifier<S extends string = string> {
	readonly #options: Options<S>;

	constructor(options: Options<S>) {
		this.#options = options;
	}

	async verify(token: string): Promise<Verified<S>> {
		const { scopes = [], ...rest } = this.#options;
		const claims = await AccessToken.verify(token, rest);
		let scope: string[];
		try {
			scope = Scope.parse(claims.scope);
		} catch {
			throw new InvalidToken('token is invalid');
		}
		return { ...claims, scope, granted: Scope.filter(scope, scopes) };
	}

	/** Verify the bearer token in `Authorization`; a missing one throws `InvalidToken`. */
	async verifyRequest(headers: Headers): Promise<Verified<S>> {
		const token = Bearer.extract(headers);
		if (token === undefined) throw new InvalidToken();
		return this.verify(token);
	}
}

export const make = <const S extends string = string>(options: Options<S>): AccessTokenVerifier<S> =>
	new AccessTokenVerifier(options);
