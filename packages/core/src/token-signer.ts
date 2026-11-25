import * as AccessToken from './access-token.ts';
import * as IdToken from './id-token.ts';

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

	signIdToken(claims: IdToken.Claims, perCall?: Omit<IdToken.SignOptions, Bound>): Promise<string> {
		return IdToken.sign(claims, { ...perCall, ...this.#options });
	}

	signAccessToken(claims: AccessToken.Claims, perCall?: Omit<AccessToken.SignOptions, Bound>): Promise<string> {
		return AccessToken.sign(claims, { ...perCall, ...this.#options });
	}
}

export const make = (options: Options): TokenSigner => new TokenSigner(options);
