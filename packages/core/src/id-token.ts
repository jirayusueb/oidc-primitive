import { base64url, errors, jwtVerify, SignJWT } from 'jose';
import type { JWTPayload } from 'jose';
import { sha256 } from './internal/crypto.ts';
import { guardKeys } from './internal/key-errors.ts';
import { unwrap } from './internal/unwrap.ts';
import { tokenAlgorithms } from './keys.ts';
import type { VerifyKey } from './keys.ts';
import { InvalidRequest } from './oauth-error.ts';
import type { Redacted } from './redacted.ts';

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
	/** Seconds from now, or a jose time span such as `"10m"`. Default `defaultLifetime`. */
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
	/** Seconds (default 30). */
	readonly clockTolerance?: number;
}

/** The claims every verified ID token carries (OIDC Core s2). */
export interface VerifiedClaims {
	readonly iss: string;
	readonly sub: string;
	readonly aud: string | string[];
	readonly iat: number;
	readonly exp: number;
	readonly [claim: string]: unknown;
}

/** Default ID token lifetime in seconds. */
export const defaultLifetime = 600;

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
	const iat = Math.floor(Date.now() / 1000);
	const expiresIn = options.expiresIn ?? defaultLifetime;
	return new SignJWT(payload)
		.setProtectedHeader({ alg: options.alg, kid: options.kid })
		.setIssuer(options.issuer)
		.setIssuedAt(iat)
		.setExpirationTime(typeof expiresIn === 'number' ? iat + expiresIn : expiresIn)
		.sign(options.key);
};

const invalid = (): InvalidRequest => new InvalidRequest('id_token_hint is invalid');

/** OIDC Core s2: `iss` and `sub` are strings, `iat` and `exp` numbers. jose has checked `iss` and `aud` values. */
const narrow = (payload: JWTPayload): VerifiedClaims => {
	const { iss, sub, aud, iat, exp } = payload;
	if (typeof iss !== 'string' || typeof sub !== 'string' || typeof iat !== 'number' || typeof exp !== 'number' || aud === undefined) {
		throw invalid();
	}
	return { ...payload, iss, sub, aud, iat, exp };
};

/** Verify an ID token, for `id_token_hint`. Any failure throws `InvalidRequest`. */
export const verify = async (jwt: string, options: VerifyOptions): Promise<VerifiedClaims> => {
	const algorithms = options.algorithms ?? tokenAlgorithms;
	if (algorithms.some((alg) => !tokenAlgorithms.includes(alg))) {
		throw new TypeError('IdToken.verify algorithms must be within the allow-list');
	}
	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(jwt, guardKeys(options.keys), {
			issuer: options.issuer,
			audience: options.audience,
			algorithms: [...algorithms],
			clockTolerance: options.clockTolerance ?? 30,
			requiredClaims: ['sub', 'iat', 'exp'],
		}));
	} catch (error) {
		// jose validates claims after the signature, so the payload on JWTExpired is authentic.
		if (!(options.allowExpired && error instanceof errors.JWTExpired)) throw invalid();
		payload = error.payload;
	}
	return narrow(payload);
};
