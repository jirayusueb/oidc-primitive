import { calculateJwkThumbprint, createLocalJWKSet, createRemoteJWKSet, exportJWK, generateKeyPair } from 'jose';
import type { JWK, JWTVerifyGetKey, RemoteJWKSetOptions } from 'jose';

/** Algorithms accepted for tokens this library signs and verifies (design D9). Frozen: nothing can widen it. */
export const tokenAlgorithms: readonly string[] = Object.freeze(['ES256', 'EdDSA', 'PS256', 'RS256']);

/** Asymmetric algorithms accepted for client assertions and advertised in metadata (RFC 8725 s3.1). */
export const assertionAlgorithms: readonly string[] = Object.freeze([
	'ES256',
	'ES384',
	'ES512',
	'EdDSA',
	'PS256',
	'PS384',
	'PS512',
	'RS256',
	'RS384',
	'RS512',
]);

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

/** What token verification accepts: a public key, or a resolver from `localResolver` / `remoteResolver`. */
export type VerifyKey = CryptoKey | JWK | JWTVerifyGetKey;

/** A resolver over a JWK Set held locally, for example a client's registered `jwks`. */
export const localResolver = (set: { readonly keys: ReadonlyArray<JWK> }): JWTVerifyGetKey => createLocalJWKSet({ keys: [...set.keys] })

/** A caching resolver over a remote `jwks_uri`; jose refetches once on an unknown `kid`. */
export const remoteResolver = (url: string | URL, options?: RemoteJWKSetOptions): JWTVerifyGetKey => createRemoteJWKSet(new URL(url), options)
