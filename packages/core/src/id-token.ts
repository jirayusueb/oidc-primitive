import { base64url, errors, jwtVerify, SignJWT } from 'jose';
import type { JWTPayload, JWTVerifyGetKey } from 'jose';
import { sha256 } from './internal/crypto.ts';
import { allowedAlgorithms } from './keys.ts';
import type { VerifyKey } from './keys.ts';
import { InvalidRequest } from './oauth-error.ts';
import { Redacted, unwrap } from './redacted.ts';

export interface Claims {
	readonly sub: string;
	readonly aud: string | string[];
	readonly nonce?: string;
	readonly auth_time?: number;
	readonly acr?: string;
	readonly amr?: string[];
	readonly iss?: never;
	readonly iat?: never;
	readonly exp?: never;
	readonly [claim: string]: unknown;
}

export interface SignOptions {
	readonly issuer: string;
	readonly key: CryptoKey;
	readonly kid: string;
	readonly alg: string;
	/** Required when `aud` has several values; becomes `azp`. */
	readonly clientId?: string;
	/** A jose time span (default `"10m"`) or an absolute epoch-seconds number. */
	readonly expiresIn?: string | number;
	/** Adds `at_hash` for the access token issued with this ID token. */
	readonly accessToken?: string | Redacted<string>;
}

export interface VerifyOptions {
	readonly issuer: string;
	readonly audience: string;
	readonly keys: VerifyKey;
	/** Accept an expired token (id_token_hint, OIDC Core s3.1.2.1). Signature, issuer and audience still apply. */
	readonly allowExpired?: boolean;
	readonly algorithms?: readonly string[];
}

const hashBits: Record<string, string> = {
	'256': 'SHA-256',
	'384': 'SHA-384',
	'512': 'SHA-512',
};

/** OIDC Core s3.1.3.6: left half of the hash that matches the signing algorithm's hash size, base64url. */
export const atHash = async (accessToken: string | Redacted<string>, alg: string): Promise<string> => {
	const bits = alg === 'EdDSA' ? '512' : /^(?:ES|RS|PS)(256|384|512)K?$/.exec(alg)?.[1];
	const name = bits === undefined ? undefined : hashBits[bits];
	if (name === undefined) throw new TypeError(`no at_hash hash for algorithm "${alg}"`);
	const digest =
		name === 'SHA-256'
			? await sha256(unwrap(accessToken))
			: new Uint8Array(await crypto.subtle.digest(name, new TextEncoder().encode(unwrap(accessToken))));
	return base64url.encode(digest.subarray(0, digest.length / 2));
};

/** Sign an ID token. The library sets `iss`, `iat`, `exp`, `azp` and `at_hash`. */
export const sign = async (claims: Claims, options: SignOptions): Promise<string> => {
	const multiple = Array.isArray(claims.aud) && claims.aud.length > 1;
	// OIDC Core s2: `azp` is the client_id of the party the token was issued to, and `aud` contains it.
	if (multiple && (options.clientId === undefined || !claims.aud.includes(options.clientId))) {
		throw new TypeError('IdToken.sign needs a clientId contained in aud when aud has several values');
	}
	const payload: JWTPayload = { ...claims };
	if (multiple) payload.azp = options.clientId as string;
	if (options.accessToken !== undefined) payload.at_hash = await atHash(options.accessToken, options.alg);
	return new SignJWT(payload)
		.setProtectedHeader({ alg: options.alg, kid: options.kid })
		.setIssuer(options.issuer)
		.setIssuedAt()
		.setExpirationTime(options.expiresIn ?? '10m')
		.sign(options.key);
};

/** Verify an ID token, for `id_token_hint`. Any failure throws `InvalidRequest`. */
export const verify = async (jwt: string, options: VerifyOptions): Promise<JWTPayload> => {
	const algorithms = options.algorithms ?? allowedAlgorithms;
	if (algorithms.some((alg) => !allowedAlgorithms.includes(alg))) {
		throw new TypeError('IdToken.verify algorithms must be within the allow-list');
	}
	try {
		const { payload } = await jwtVerify(jwt, options.keys as JWTVerifyGetKey, {
			issuer: options.issuer,
			audience: options.audience,
			algorithms: [...algorithms],
			requiredClaims: ['sub', 'iat', 'exp'],
		});
		return payload;
	} catch (error) {
		// jose validates claims after the signature, so the payload on JWTExpired is authentic.
		if (options.allowExpired && error instanceof errors.JWTExpired) return error.payload;
		throw new InvalidRequest('id_token_hint is invalid');
	}
};
