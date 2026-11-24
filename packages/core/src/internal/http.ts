import { Redacted, unwrap } from '../redacted.ts';

export type ParamValue = string | number | Redacted<string> | undefined;

/** RFC 6750 s3: auth-param values allow %x20-21 / %x23-5B / %x5D-7E. */
const challengeValue = /^[\x20\x21\x23-\x5B\x5D-\x7E]*$/;

export const noStoreHeaders = (): Headers =>
	new Headers({
		'Content-Type': 'application/json;charset=UTF-8',
		'Cache-Control': 'no-store',
		Pragma: 'no-cache',
	});

/** JSON response; `Redacted` values are written raw (toJSON runs before a replacer, so read the holder). */
export const json = (body: unknown, status = 200, headers: Headers = noStoreHeaders()): Response =>
	new Response(
		JSON.stringify(body, function (this: Record<string, unknown>, key: string, value: unknown) {
			const raw = this[key];
			return raw instanceof Redacted ? Redacted.value(raw) : value;
		}),
		{ status, headers },
	);

export const challenge = (scheme: string, params: Record<string, string | undefined>): string => {
	const parts: string[] = [];
	for (const [key, value] of Object.entries(params)) {
		if (value === undefined) continue;
		if (!challengeValue.test(value)) {
			throw new TypeError(`WWW-Authenticate parameter "${key}" has characters outside RFC 6750 s3`);
		}
		parts.push(`${key}="${value}"`);
	}
	return parts.length === 0 ? scheme : `${scheme} ${parts.join(', ')}`;
};

/** 303 redirect carrying `params` in the query plus `iss` (RFC 9207). */
export const redirect = (
	redirectUri: string,
	params: Record<string, ParamValue>,
	issuer: string,
): Response => {
	const url = new URL(redirectUri);
	for (const [key, value] of Object.entries({ ...params, iss: issuer })) {
		if (value !== undefined) url.searchParams.set(key, String(unwrap(value)));
	}
	return new Response(null, {
		status: 303,
		headers: { Location: url.href, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' },
	});
};
