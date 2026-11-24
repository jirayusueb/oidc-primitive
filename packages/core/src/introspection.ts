import { json } from './oauth-response.ts';

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

/** RFC 7662 s2.2 response for a live token; extra claims pass through, `active` cannot be overridden. */
export const active = (claims: Claims): Record<string, unknown> => {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(claims)) if (value !== undefined) out[key] = value;
	return { ...out, active: true };
};

/** RFC 7662 s2.2: an unknown, expired or foreign token reveals nothing else. */
export const inactive = (): { active: false } => ({ active: false });

/** No-store JSON response. */
export const response = (body: Record<string, unknown>): Response => json(body);
