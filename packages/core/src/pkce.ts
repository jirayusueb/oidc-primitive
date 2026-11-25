import { digestEqual, sha256Base64url } from './internal/crypto.ts';
import { InvalidGrant, InvalidRequest } from './oauth-error.ts';

/** RFC 7636 s4.1: 43-128 characters from [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". */
const verifierPattern = /^[A-Za-z0-9\-._~]{43,128}$/;
/** RFC 7636 s4.2: BASE64URL(SHA256(verifier)) is 43 characters. */
const challengePattern = /^[A-Za-z0-9\-_]{43}$/;

export const isVerifier = (value: unknown): value is string =>
	typeof value === 'string' && verifierPattern.test(value);

export const isChallenge = (value: unknown): value is string =>
	typeof value === 'string' && challengePattern.test(value);

/** The S256 code challenge for `verifier` (RFC 7636 s4.2). */
export const deriveChallenge = async (verifier: string): Promise<string> => {
	if (!isVerifier(verifier)) throw new InvalidRequest('code_verifier is malformed');
	return sha256Base64url(verifier);
};

/**
 * Check the authorization request's challenge method. Only S256 is accepted
 * (RFC 9700 s2.1.1, OAuth 2.1 draft-17 s4.1.1); an absent method means `plain`.
 */
export const validateMethod = (method: string | null | undefined): void => {
	if (method !== 'S256') throw new InvalidRequest('code_challenge_method must be S256');
};

export interface VerifyOptions {
	/** When true (default) both values must be present. Exemptions are host policy (RFC 9700 s2.1.1). */
	readonly required?: boolean;
}

/**
 * Verify a token request's `code_verifier` against the stored `code_challenge`.
 * A verifier without a stored challenge is rejected (downgrade, RFC 9700 s4.8.2).
 */
export const verify = async (
	verifier: string | null | undefined,
	storedChallenge: string | null | undefined,
	options: VerifyOptions = {},
): Promise<void> => {
	const hasVerifier = verifier !== undefined && verifier !== null;
	const hasChallenge = storedChallenge !== undefined && storedChallenge !== null;
	if (!hasVerifier && !hasChallenge) {
		if (options.required ?? true) throw new InvalidGrant('PKCE is required');
		return;
	}
	if (!hasChallenge) throw new InvalidGrant('code_verifier sent without a code_challenge');
	if (!hasVerifier) throw new InvalidGrant('code_verifier is required');
	if (!isVerifier(verifier)) throw new InvalidGrant('code_verifier is malformed');
	if (!(await digestEqual(await sha256Base64url(verifier), storedChallenge))) {
		throw new InvalidGrant('code_verifier does not match');
	}
};
