import * as AccessToken from './AccessToken.ts';
import * as IdToken from './IdToken.ts';

export interface Options {
	readonly issuer: string;
	readonly key: CryptoKey;
	readonly kid: string;
	readonly alg: string;
}

type Bound = keyof Options;

/** A signing key bound to an issuer. Per-client values (`clientId`, `accessToken`) stay per call. */
export class TokenSigner {
	readonly #options: Options;

	constructor(options: Options) {
		this.#options = options;
	}

	idToken(claims: IdToken.Claims, perCall?: Omit<IdToken.SignOptions, Bound>): Promise<string> {
		return IdToken.sign(claims, { ...perCall, ...this.#options });
	}

	accessToken(claims: AccessToken.Claims, perCall?: Omit<AccessToken.SignOptions, Bound>): Promise<string> {
		return AccessToken.sign(claims, { ...perCall, ...this.#options });
	}
}

export const make = (options: Options): TokenSigner => new TokenSigner(options);
