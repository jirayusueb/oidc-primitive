import { challenge as formatChallenge } from './internal/http.ts';
import { InvalidToken } from './oauth-error.ts';

/** RFC 6750 s2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=". */
const bearer = /^Bearer +([A-Za-z0-9\-._~+/]+=*)$/i;

/**
 * The bearer token from the `Authorization` header only; query and body are never read
 * (RFC 6750 s2.1). Returns `undefined` when no Bearer credential is present and throws
 * `InvalidToken` when one is malformed.
 */
export const extract = (headers: Headers): string | undefined => {
	const value = headers.get('authorization');
	if (value === null || !/^Bearer(?: |$)/i.test(value)) return undefined;
	const match = bearer.exec(value);
	if (match === null) throw new InvalidToken('malformed bearer credential');
	return match[1];
};

export interface ChallengeOptions {
	readonly realm?: string;
	readonly error?: string;
	readonly error_description?: string;
	readonly scope?: string;
	/** RFC 9728 s5.1. */
	readonly resource_metadata?: string;
}

/** A `WWW-Authenticate: Bearer` value (RFC 6750 s3). Throws on characters outside s3. */
export const challenge = (options: ChallengeOptions = {}): string =>
	formatChallenge('Bearer', {
		realm: options.realm,
		error: options.error,
		error_description: options.error_description,
		scope: options.scope,
		resource_metadata: options.resource_metadata,
	});
