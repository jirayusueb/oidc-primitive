import { InvalidRequest } from './oauth-error.ts';

export type Target = 'userinfo' | 'id_token';
export type RequestMap = Readonly<Record<string, unknown>>;
export interface ClaimsRequest {
	readonly userinfo?: RequestMap;
	readonly id_token?: RequestMap;
}

/** OIDC Core s5.4. */
const byScope: Readonly<Record<string, readonly string[]>> = {
	profile: [
		'name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile',
		'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at',
	],
	email: ['email', 'email_verified'],
	address: ['address'],
	phone: ['phone_number', 'phone_number_verified'],
};

/** Standard claim names the given scopes grant. Unknown scopes grant none. */
export const forScopes = (scopes: Iterable<string>): string[] => {
	const out = new Set<string>();
	for (const scope of scopes) {
		if (Object.hasOwn(byScope, scope)) for (const name of byScope[scope]!) out.add(name);
	}
	return [...out];
};

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && value !== null && !Array.isArray(value);

const parseMap = (value: unknown): RequestMap | undefined => {
	if (value === undefined || value === null) return undefined;
	if (!isObject(value)) throw new InvalidRequest('claims parameter is malformed');
	const out: Record<string, unknown> = Object.create(null);
	for (const [name, spec] of Object.entries(value)) {
		if (spec !== null && !isObject(spec)) throw new InvalidRequest('claims parameter is malformed');
		out[name] = spec;
	}
	return out;
};

/** OIDC Core s5.5: parse the `claims` request parameter. */
export const parseRequest = (json: string | null | undefined): ClaimsRequest => {
	if (json === null || json === undefined) return {};
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		throw new InvalidRequest('claims parameter is not valid JSON');
	}
	if (!isObject(parsed)) throw new InvalidRequest('claims parameter is malformed');
	const userinfo = parseMap(parsed.userinfo);
	const id_token = parseMap(parsed.id_token);
	return { ...(userinfo && { userinfo }), ...(id_token && { id_token }) };
};

export interface SelectOptions {
	readonly scopes: Iterable<string>;
	readonly request?: ClaimsRequest;
	readonly target: Target;
}

/** Only claims granted by scope or requested for `target`; `sub` is always kept. */
export const select = (
	claims: Readonly<Record<string, unknown>>,
	options: SelectOptions,
): Record<string, unknown> => {
	const allowed = new Set(forScopes(options.scopes));
	for (const name of Object.keys(options.request?.[options.target] ?? {})) allowed.add(name);
	allowed.add('sub');
	const out: Record<string, unknown> = {};
	for (const name of allowed) if (Object.hasOwn(claims, name) && claims[name] !== undefined) out[name] = claims[name];
	return out;
};
