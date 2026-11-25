---
title: Keys
description: Generate signing keys, publish a public JWK Set, and resolve verification keys.
---

`Keys` generates signing key pairs, builds the `jwks_uri` document without private members ([RFC 7517 section 5](https://www.rfc-editor.org/rfc/rfc7517#section-5)), computes [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprints, and resolves keys for [AccessToken](/reference/access-token/), [IdToken](/reference/id-token/) and [ClientAssertion](/reference/client-assertion/). See [tokens and keys](/guide/tokens-and-keys/).

## Import

```ts
import { Keys } from 'oidc-primitive';
```

## tokenAlgorithms

```ts title="signature"
const tokenAlgorithms: readonly string[];
```

The frozen allow-list for tokens this library signs and verifies: `ES256`, `EdDSA`, `PS256`, `RS256`. `AccessToken.verify` and `IdToken.verify` use it by default and reject any `algorithms` option outside it. Nothing can widen it.

## assertionAlgorithms

```ts title="signature"
const assertionAlgorithms: readonly string[];
```

The frozen list of asymmetric algorithms accepted for client assertions and advertised in metadata: `ES256`, `ES384`, `ES512`, `EdDSA`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`. `HS*` and `none` are never accepted. `ClientAssertion.verify` and `ServerMetadata.make` use it.

## KeyPair

```ts title="signature"
interface KeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
}
```

## Entry

```ts title="signature"
interface Entry {
  readonly key: CryptoKey | JWK;
  readonly kid: string;
  readonly alg: string;
}
```

One public key to publish in a JWK Set.

## generate

```ts title="signature"
const generate: (
  alg?: string,
  options?: { readonly extractable?: boolean },
) => Promise<KeyPair>;
```

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `alg` | `string` | `'RS256'` | JOSE algorithm of the new key pair. |
| `options.extractable` | `boolean` | `false` | Whether the private key can be exported. |

```ts
const { publicKey, privateKey } = await Keys.generate('ES256');
```

## publicJwk

```ts title="signature"
const publicJwk: (
  publicKey: CryptoKey | JWK,
  options: { readonly kid: string; readonly alg: string },
) => Promise<JWK>;
```

Returns the public JWK with `kid`, `alg` and `use: "sig"` set. Throws `TypeError` (`refusing to publish a JWK with private member "<name>"`) when the input has any of `d`, `p`, `q`, `dp`, `dq`, `qi`, `k` or `oth`.

## jwks

```ts title="signature"
const jwks: (entries: ReadonlyArray<Entry>) => Promise<{ keys: JWK[] }>;
```

Returns a JWK Set built with `publicJwk` for each entry. Serve it at your `jwks_uri`. It throws for the same reason `publicJwk` does.

```ts
const set = await Keys.jwks([{ key: publicKey, kid: 'k1', alg: 'ES256' }]);
return new Response(JSON.stringify(set), { headers: { 'Content-Type': 'application/json' } });
```

## thumbprint

```ts title="signature"
const thumbprint: (jwk: JWK) => Promise<string>;
```

The [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint, SHA-256, base64url.

```ts
const jkt = await Keys.thumbprint(await Keys.publicJwk(publicKey, { kid: 'k1', alg: 'ES256' }));
```

## VerifyKey

```ts title="signature"
type VerifyKey = CryptoKey | JWK | JWTVerifyGetKey;
```

What token verification accepts: a public key, a JWK, or a resolver from `localResolver` or `remoteResolver`.

## localResolver

```ts title="signature"
const localResolver: (set: { readonly keys: ReadonlyArray<JWK> }) => JWTVerifyGetKey;
```

A resolver over a JWK Set held locally, for example a client's registered `jwks`.

```ts
const keys = Keys.localResolver(await Keys.jwks([{ key: publicKey, kid: 'k1', alg: 'ES256' }]));
```

## remoteResolver

```ts title="signature"
const remoteResolver: (url: string | URL, options?: RemoteJWKSetOptions) => JWTVerifyGetKey;
```

A caching resolver over a remote `jwks_uri`. jose refetches once on an unknown `kid`. `options` is jose's `RemoteJWKSetOptions`. Fetch failures surface as `OAuthError.TemporarilyUnavailable` from the verifier that uses the resolver.

```ts
const keys = Keys.remoteResolver('https://client.example.com/jwks');
```

## Spec

- [RFC 7517 section 5](https://www.rfc-editor.org/rfc/rfc7517#section-5): JWK Set publishing.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JWK thumbprint.
