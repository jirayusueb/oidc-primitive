import { errors } from 'jose';

/**
 * True when verification failed because the key set could not be fetched, not because the
 * token is bad. Callers answer 503 so a key-server outage does not look like a bad credential.
 */
export const isKeyFetchFailure = (error: unknown): boolean =>
	error instanceof errors.JWKSTimeout ||
	!(error instanceof errors.JOSEError) ||
	error.code === 'ERR_JOSE_GENERIC';
