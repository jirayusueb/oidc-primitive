import { InvalidRequest } from './OAuthError.ts';

export type ApplicationType = 'web' | 'native';

const loopbackHosts = ['127.0.0.1', '[::1]'];
const devHosts = [...loopbackHosts, 'localhost'];
const forbiddenSchemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:'];

/**
 * Check a redirect URI at registration time.
 * No fragment (RFC 6749 s3.1.2). `http` only on loopback or localhost (RFC 9700 s2.6,
 * RFC 8252 s7.3). Private-use schemes only for native clients (RFC 8252 s7.1).
 */
export const validate = (uri: string, options: { readonly applicationType?: ApplicationType } = {}): void => {
	if (!URL.canParse(uri)) throw new InvalidRequest('redirect_uri is not an absolute URI');
	const url = new URL(uri);
	const type = options.applicationType ?? 'web';
	if (uri.includes('#')) throw new InvalidRequest('redirect_uri must not contain a fragment');
	if (url.protocol === 'https:') return;
	if (url.protocol === 'http:') {
		if (devHosts.includes(url.hostname)) return;
		throw new InvalidRequest('redirect_uri must use https outside loopback');
	}
	if (type === 'native' && !forbiddenSchemes.includes(url.protocol)) return;
	throw new InvalidRequest('redirect_uri scheme is not allowed');
};

const isLoopback = (url: URL): boolean => url.protocol === 'http:' && loopbackHosts.includes(url.hostname);

/**
 * Exact string comparison against registered URIs (RFC 9700 s4.1.3). The only
 * exception is the port of `http://127.0.0.1` and `http://[::1]` (RFC 8252 s7.3).
 * Returns the registered URI that matched.
 */
export const match = (requested: string, registered: ReadonlyArray<string>): string | undefined => {
	if (registered.includes(requested)) return requested;
	if (!URL.canParse(requested)) return undefined;
	const req = new URL(requested);
	if (!isLoopback(req)) return undefined;
	return registered.find((candidate) => {
		if (!URL.canParse(candidate)) return false;
		const reg = new URL(candidate);
		if (!isLoopback(reg) || reg.hostname !== req.hostname) return false;
		reg.port = '';
		const portless = new URL(requested);
		portless.port = '';
		return reg.href === portless.href;
	});
};

/** True when `requested` matches a registered URI under `match`. */
export const matches = (requested: string, registered: ReadonlyArray<string>): boolean =>
	match(requested, registered) !== undefined;
