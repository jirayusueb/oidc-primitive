import { InvalidClient } from './oauth-error.ts';
import { Redacted } from './redacted.ts';

export interface BasicCredentials {
	readonly clientId: string;
	readonly clientSecret: Redacted<string>;
}

/** application/x-www-form-urlencoded decoding (RFC 6749 s2.3.1, Appendix B). */
const formDecode = (value: string): string => decodeURIComponent(value.replaceAll('+', ' '));

/**
 * Parse `Authorization: Basic` client credentials (RFC 6749 s2.3.1). Returns `undefined`
 * when the header is absent or uses another scheme; throws `InvalidClient` when malformed.
 */
export const parseBasic = (header: string | null | undefined): BasicCredentials | undefined => {
	if (!header) return undefined;
	const [scheme, encoded, ...rest] = header.trim().split(/\s+/);
	if (scheme?.toLowerCase() !== 'basic') return undefined;
	if (!encoded || rest.length > 0) throw new InvalidClient('malformed Basic credentials');
	let decoded: string;
	try {
		decoded = new TextDecoder('utf-8', { fatal: true }).decode(
			Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)),
		);
	} catch {
		throw new InvalidClient('malformed Basic credentials');
	}
	const colon = decoded.indexOf(':');
	if (colon <= 0) throw new InvalidClient('malformed Basic credentials');
	try {
		return {
			clientId: formDecode(decoded.slice(0, colon)),
			clientSecret: Redacted.make(formDecode(decoded.slice(colon + 1))),
		};
	} catch {
		throw new InvalidClient('malformed Basic credentials');
	}
};
