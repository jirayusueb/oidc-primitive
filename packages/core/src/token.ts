import { base64url } from 'jose';
import { digestEqual, sha256Base64url } from './internal/crypto.ts';
import { Redacted, unwrap } from './redacted.ts';

/**
 * Opaque credentials: authorization codes, refresh tokens, opaque access tokens and
 * client secrets (RFC 6749 s10.10). Store `hash(value)`, never the value.
 */

/** A random base64url credential of `bytes` random bytes (default 32, minimum 16). */
export const generate = (bytes = 32): Redacted<string> => {
	if (!Number.isInteger(bytes) || bytes < 16) throw new RangeError('Token.generate needs at least 16 bytes');
	return Redacted.make(base64url.encode(crypto.getRandomValues(new Uint8Array(bytes))));
};

/** SHA-256 of the credential, base64url encoded. Use it as the storage key. */
export const hash = (value: string | Redacted<string>): Promise<string> => sha256Base64url(unwrap(value));

/** Constant-time comparison of two credentials. */
export const equals = (a: string | Redacted<string>, b: string | Redacted<string>): Promise<boolean> =>
	digestEqual(unwrap(a), unwrap(b));

/** Constant-time check of a presented credential against a stored `hash`. */
export const matchesHash = async (presented: string | Redacted<string>, storedHash: string): Promise<boolean> =>
	digestEqual(await hash(presented), storedHash);
