import { InvalidTarget } from './OAuthError.ts';

/** RFC 8707 s2: an absolute URI without a fragment. */
export const validate = (uri: string): string => {
	if (!URL.canParse(uri) || uri.includes('#')) {
		throw new InvalidTarget('resource must be an absolute URI without a fragment');
	}
	return uri;
};

/**
 * The access token audience for the requested `resource` values: the single resource,
 * or `issuer` when none was sent. Several values are rejected, since one token serves
 * one audience (RFC 8707 s2, RFC 9700 s2.3).
 */
export const audience = (resources: ReadonlyArray<string>, issuer: string): string => {
	const unique = [...new Set(resources)];
	if (unique.length === 0) return issuer;
	if (unique.length > 1) throw new InvalidTarget('only one resource is supported per request');
	return validate(unique[0] as string);
};
