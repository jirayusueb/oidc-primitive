import { type CryptoKey, type JWTVerifyGetKey, jwtVerify } from 'jose';
import { InvalidClient } from './OAuthError.ts';

/** RFC 7521 s4.2 `client_assertion_type` for JWT bearer assertions. */
export const assertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export const algorithms: readonly string[] = [
	'ES256', 'EdDSA', 'PS256', 'RS256', 'ES384', 'ES512', 'PS384', 'PS512', 'RS384', 'RS512',
];

export interface VerifyOptions {
	readonly issuer: string;
	readonly clientId: string;
	/** A `CryptoKey` or a jose key resolver such as `createRemoteJWKSet` or `createLocalJWKSet`. */
	readonly keys: CryptoKey | JWTVerifyGetKey;
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

const fail = (): InvalidClient => new InvalidClient('Client assertion is invalid');

/** RFC 7523 s3 and RFC 10070 s4: `aud` is exactly the issuer identifier. Replay checking stays with the host. */
export const verify = async (jwt: string, options: VerifyOptions): Promise<Verified> => {
	const { issuer, clientId, keys, clockTolerance = 30, maxLifetime = 600, currentDate } = options;
	try {
		const { payload } = await jwtVerify(jwt, keys as JWTVerifyGetKey, {
			algorithms: [...algorithms],
			issuer: clientId,
			subject: clientId,
			audience: issuer,
			requiredClaims: ['iss', 'sub', 'aud', 'exp', 'jti'],
			clockTolerance,
			currentDate,
		});
		const aud = payload.aud;
		const audOk = aud === issuer || (Array.isArray(aud) && aud.length === 1 && aud[0] === issuer);
		const now = Math.floor((currentDate ?? new Date()).getTime() / 1000);
		const { exp, jti } = payload;
		if (!audOk || typeof exp !== 'number' || !jti || exp - now > maxLifetime) throw fail();
		return { jti, expiresAt: exp };
	} catch {
		throw fail();
	}
};
