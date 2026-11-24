import { errors } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import type { VerifyKey } from '../keys.ts';

/** Thrown by a guarded key resolver when the key set could not be fetched. */
class KeyFetchFailure extends Error {}

/**
 * True when verification failed because the key set could not be fetched, not because the
 * token is bad. Callers answer 503 so a key-server outage does not look like a bad credential.
 */
export const isKeyFetchFailure = (error: unknown): boolean => error instanceof KeyFetchFailure;

/** A fetch or timeout failure from a resolver. Other jose errors (unknown `kid`, bad key) are the token's fault. */
const isFetchError = (error: unknown): boolean =>
	error instanceof errors.JWKSTimeout ||
	!(error instanceof errors.JOSEError) ||
	error.code === 'ERR_JOSE_GENERIC';

/**
 * The resolver `jwtVerify` receives. Only a resolver function can report a fetch failure;
 * a `CryptoKey` or `JWK` never does, so a forged header cannot trigger a 503.
 */
export const guardKeys = (keys: VerifyKey): JWTVerifyGetKey => {
	if (typeof keys !== 'function') return keys as unknown as JWTVerifyGetKey;
	return async (header, token) => {
		try {
			return await keys(header, token);
		} catch (error) {
			throw isFetchError(error) ? new KeyFetchFailure('key set unavailable') : error;
		}
	};
};
