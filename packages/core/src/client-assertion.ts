import { type JWTPayload, jwtVerify } from 'jose';
import { guardKeys, isKeyFetchFailure } from './internal/key-errors.ts';
import { assertionAlgorithms } from './keys.ts';
import type { VerifyKey } from './keys.ts';
import { InvalidClient, TemporarilyUnavailable } from './oauth-error.ts';

/** RFC 7521 s4.2 `client_assertion_type` for JWT bearer assertions. */
export const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface VerifyOptions {
	readonly issuer: string;
	readonly clientId: string;
	/** A public key, or a resolver from `Keys.remoteSet` (a `jwks_uri`) or `Keys.localSet` (registered `jwks`). */
	readonly keys: VerifyKey;
	/** Seconds of clock skew, default 30. */
	readonly clockTolerance?: number;
	/** Maximum seconds `exp` may lie ahead, default 600. */
	readonly maxLifetime?: number;
	readonly currentDate?: Date;
}

export interface Verified {
	readonly jti: string;
	/** Epoch seconds; keep the `jti` until then to reject replays. */
	readonly expiresAt: number;
}

const fail = (): InvalidClient => new InvalidClient('client assertion is invalid');

/** RFC 7523 s3 and RFC 10070 s4: `aud` is exactly the issuer identifier. Replay checking stays with the host. */
export const verify = async (jwt: string, options: VerifyOptions): Promise<Verified> => {
	const { issuer, clientId, keys, clockTolerance = 30, maxLifetime = 600, currentDate } = options;
	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(jwt, guardKeys(keys), {
			algorithms: [...assertionAlgorithms],
			issuer: clientId,
			subject: clientId,
			audience: issuer,
			requiredClaims: ['iss', 'sub', 'aud', 'exp', 'jti'],
			clockTolerance,
			currentDate,
		}));
	} catch (error) {
		if (isKeyFetchFailure(error)) throw new TemporarilyUnavailable('client keys are unavailable');
		throw fail();
	}
	const { aud, exp, jti } = payload;
	const audOk = aud === issuer || (Array.isArray(aud) && aud.length === 1 && aud[0] === issuer);
	const now = Math.floor((currentDate ?? new Date()).getTime() / 1000);
	// RFC 7519 s4.1.7: `jti` is a case-sensitive string; the host keys its replay record on it.
	if (!audOk || typeof exp !== 'number' || typeof jti !== 'string' || jti === '' || exp - now > maxLifetime) {
		throw fail();
	}
	return { jti, expiresAt: exp };
};
