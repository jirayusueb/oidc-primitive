import { base64url } from 'jose';

const encoder = new TextEncoder();

export const sha256 = async (value: string): Promise<Uint8Array> =>
	new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));

export const sha256Base64url = async (value: string): Promise<string> =>
	base64url.encode(await sha256(value));

/** Compare equal-length byte arrays without an early exit. */
export const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
	return diff === 0;
};

/** Compare two strings through their SHA-256 digests, so timing reveals nothing about either. */
export const digestEqual = async (a: string, b: string): Promise<boolean> =>
	timingSafeEqual(await sha256(a), await sha256(b));
