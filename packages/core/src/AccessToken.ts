import { errors, jwtVerify, SignJWT } from 'jose';
import type { JWTPayload, JWTVerifyGetKey } from 'jose';
import { allowedAlgorithms } from './Keys.ts';
import type { VerifyKey } from './Keys.ts';
import { InvalidToken, OAuthError } from './OAuthError.ts';

export interface Claims {
	readonly sub: string;
	readonly aud: string | string[];
	readonly client_id: string;
	/** Space-delimited scopes (RFC 9068 s2.2.3). */
	readonly scope?: string;
	readonly cnf?: Record<string, unknown>;
	readonly iss?: never;
	readonly iat?: never;
	readonly exp?: never;
	readonly jti?: never;
	readonly [claim: string]: unknown;
}

export interface SignOptions {
	readonly issuer: string;
	readonly key: CryptoKey;
	readonly kid: string;
	readonly alg: string;
	/** A jose time span (default `"10m"`) or an absolute epoch-seconds number. */
	readonly expiresIn?: string | number;
}

export interface VerifyOptions {
	readonly issuer: string;
	readonly audience: string;
	readonly keys: VerifyKey;
	/** Narrow the D9 allow-list; values outside it throw `TypeError`. */
	readonly algorithms?: readonly string[];
	/** Seconds (default 30). */
	readonly clockTolerance?: number;
	/** Called with `cnf` of a sender-constrained token; throw to reject. Without it, such tokens are rejected. */
	readonly confirm?: (cnf: Record<string, unknown>) => void | Promise<void>;
}

export interface VerifiedClaims extends JWTPayload {
	readonly iss: string;
	readonly sub: string;
	readonly client_id: string;
	readonly jti: string;
	readonly iat: number;
	readonly exp: number;
	readonly scope?: string;
	readonly cnf?: Record<string, unknown>;
}

/** RFC 9068 JWT access token. The library sets `typ: at+jwt`, `iss`, `iat`, `exp` and `jti`. */
export const sign = (claims: Claims, options: SignOptions): Promise<string> =>
	new SignJWT({ ...claims })
		.setProtectedHeader({ alg: options.alg, kid: options.kid, typ: 'at+jwt' })
		.setIssuer(options.issuer)
		.setJti(crypto.randomUUID())
		.setIssuedAt()
		.setExpirationTime(options.expiresIn ?? '10m')
		.sign(options.key);

/** RFC 9068 s4 verification. Every failure throws `InvalidToken`, never echoing the token. */
export const verify = async (token: string, options: VerifyOptions): Promise<VerifiedClaims> => {
	const algorithms = options.algorithms ?? allowedAlgorithms;
	if (algorithms.some((alg) => !allowedAlgorithms.includes(alg))) {
		throw new TypeError('AccessToken.verify algorithms must be within the allow-list');
	}
	let payload: JWTPayload;
	try {
		({ payload } = await jwtVerify(token, options.keys as JWTVerifyGetKey, {
			issuer: options.issuer,
			audience: options.audience,
			typ: 'at+jwt',
			algorithms: [...algorithms],
			clockTolerance: options.clockTolerance ?? 30,
			requiredClaims: ['sub', 'client_id', 'jti', 'iat', 'exp'],
		}));
	} catch (error) {
		throw new InvalidToken(error instanceof errors.JWTExpired ? 'token expired' : 'token is invalid');
	}
	if (typeof payload.client_id !== 'string' || (payload.scope !== undefined && typeof payload.scope !== 'string')) {
		throw new InvalidToken('token is invalid');
	}
	if (payload.cnf !== undefined) {
		const cnf = payload.cnf;
		if (options.confirm === undefined || typeof cnf !== 'object' || cnf === null) {
			throw new InvalidToken('token is sender-constrained');
		}
		try {
			await options.confirm(cnf as Record<string, unknown>);
		} catch (error) {
			throw error instanceof OAuthError ? error : new InvalidToken('token is sender-constrained');
		}
	}
	return payload as VerifiedClaims;
};
