import {
	type ParamValue,
	json as jsonResponse,
	noStoreHeaders,
	redirect as redirectResponse,
} from './internal/http.ts';

export interface JsonInit {
	readonly status?: number;
	readonly headers?: HeadersInit;
}

/** JSON response with `Cache-Control: no-store`; `Redacted` values are unwrapped. */
export const json = (body: unknown, init: JsonInit = {}): Response => {
	const headers = noStoreHeaders();
	for (const [key, value] of new Headers(init.headers)) headers.set(key, value);
	return jsonResponse(body, init.status ?? 200, headers);
};

/** 303 redirect with `params` plus `iss` (RFC 9207). */
export const redirect = (
	redirectUri: string,
	params: Record<string, ParamValue>,
	options: { readonly issuer: string },
): Response => redirectResponse(redirectUri, params, options.issuer);
