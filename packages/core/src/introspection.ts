export interface Claims {
	readonly scope?: string;
	readonly client_id?: string;
	readonly username?: string;
	readonly token_type?: string;
	readonly exp?: number;
	readonly iat?: number;
	readonly nbf?: number;
	readonly sub?: string;
	readonly aud?: string | readonly string[];
	readonly iss?: string;
	readonly jti?: string;
	readonly [claim: string]: unknown;
}

export interface ActiveResponse extends Claims {
	readonly active: true;
}

export interface InactiveResponse {
	readonly active: false;
}

/** RFC 7662 s2.2 response for a live token; extra claims pass through, `active` cannot be overridden. */
export const active = (claims: Claims): ActiveResponse => {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(claims)) if (value !== undefined) out[key] = value;
	return { ...out, active: true } as ActiveResponse;
};

/** RFC 7662 s2.2: an unknown, expired or foreign token reveals nothing else. */
export const inactive = (): InactiveResponse => ({ active: false });
