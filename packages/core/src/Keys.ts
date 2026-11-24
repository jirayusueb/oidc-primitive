import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import type { JWK, JWTVerifyGetKey } from 'jose';

/** D9 algorithm allow-list for verifying tokens. */
export const allowedAlgorithms: readonly string[] = ['ES256', 'EdDSA', 'PS256', 'RS256'];

export interface KeyPair {
	readonly publicKey: CryptoKey;
	readonly privateKey: CryptoKey;
}

export interface Entry {
	readonly key: CryptoKey | JWK;
	readonly kid: string;
	readonly alg: string;
}

const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'] as const;

/** Generate a signing key pair. The private key is non-extractable unless asked otherwise. */
export const generate = (
	alg = 'ES256',
	{ extractable = false }: { readonly extractable?: boolean } = {},
): Promise<KeyPair> => generateKeyPair(alg, { extractable });

/** The public JWK for `publicKey` with `kid`, `alg` and `use: "sig"`. Throws if a private member would appear. */
export const publicJwk = async (
	publicKey: CryptoKey | JWK,
	{ kid, alg }: { readonly kid: string; readonly alg: string },
): Promise<JWK> => {
	const jwk = publicKey instanceof CryptoKey ? await exportJWK(publicKey) : { ...publicKey };
	for (const member of privateMembers) {
		if (member in jwk) throw new TypeError(`refusing to publish a JWK with private member "${member}"`);
	}
	return { ...jwk, kid, alg, use: 'sig' };
};

/** A JWK Set of public keys for the `jwks_uri` document. */
export const jwks = async (entries: ReadonlyArray<Entry>): Promise<{ keys: JWK[] }> => ({
	keys: await Promise.all(entries.map((entry) => publicJwk(entry.key, entry))),
});

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export const thumbprint = (jwk: JWK): Promise<string> => calculateJwkThumbprint(jwk);

/** What token verification accepts: a key, or a resolver such as `createLocalJWKSet(jwks)` / `createRemoteJWKSet(url)`. */
export type VerifyKey = CryptoKey | JWK | Uint8Array | JWTVerifyGetKey;
