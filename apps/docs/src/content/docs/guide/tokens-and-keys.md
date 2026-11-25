---
title: Tokens and keys
description: Generate signing keys, publish a JWK Set, and sign ID tokens and JWT access tokens.
---

At the token endpoint, after every check has passed, the library signs the tokens. This page covers keys, signing and rotation.

## Keys

`Keys.generate(alg, options)` returns a `{ publicKey, privateKey }` pair. The default algorithm is `RS256`, the ID token algorithm every OpenID Provider must support (OIDC Core s15.1). The private key is non-extractable unless you pass `{ extractable: true }`.

`Keys.jwks` builds the document for your `jwks_uri` from public keys. `Keys.publicJwk` refuses to publish a JWK that contains a private member.

```ts
import { Keys } from 'oidc-primitive';

const { publicKey, privateKey } = await Keys.generate('RS256');
const jwks = await Keys.jwks([{ key: publicKey, kid: 'op-1', alg: 'RS256' }]);
```

Serve `jwks` as JSON at the URL you give to [ServerMetadata](/reference/server-metadata/). See [Keys](/reference/keys/).

## TokenSigner

`TokenSigner.make` binds an issuer and a signing key. Per-call values stay per call.

```ts
import { Keys, TokenSigner } from 'oidc-primitive';

declare const issuer: string;

const { privateKey } = await Keys.generate('ES256');
const signer = TokenSigner.make({ issuer, key: privateKey, kid: 'op-1', alg: 'ES256' });
```

The `key` must be a private `CryptoKey`. See [TokenSigner](/reference/token-signer/).

## AccessToken

`signer.signAccessToken` signs an [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT. The library sets `typ: at+jwt`, `iss`, `iat`, `exp` and `jti`. You supply `sub`, `aud`, `client_id` and optionally `scope`. Use the `Resource.resolveAudience` result as `aud`. `expiresIn` defaults to `"10m"`.

```ts
import { Scope, type TokenSigner } from 'oidc-primitive';

declare const signer: TokenSigner.TokenSigner;
declare const audience: string;

const accessToken = await signer.signAccessToken(
	{ sub: 'user-1', aud: audience, client_id: 'demo', scope: Scope.format(['openid', 'profile']) },
	{ expiresIn: '5m' },
);
```

Extra claims pass through. The [Example OP](/guide/example-op/) adds a `gid` claim to find the grant at userinfo and introspection. See [AccessToken](/reference/access-token/).

## IdToken

`signer.signIdToken` signs an ID token. The library sets `iss`, `iat`, `exp`, and adds `azp` when `aud` has several values. Pass `accessToken` to add `at_hash` ([OIDC Core s3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken)).

```ts
import { type TokenSigner } from 'oidc-primitive';

declare const signer: TokenSigner.TokenSigner;
declare const accessToken: string;

const idToken = await signer.signIdToken(
	{ sub: 'user-1', aud: 'demo', nonce: 'n-0S6_WzA2Mj', auth_time: 1700000000 },
	{ accessToken },
);
```

Echo the `nonce` from the authorization request on the first token response only. Do not echo it on refresh ([OIDC Core s12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)). With several audiences, pass `clientId` and make sure `aud` contains it, or signing throws `TypeError`.

For `id_token_hint`, call `IdToken.verify(jwt, { issuer, audience, keys, allowExpired: true })`. It checks signature, issuer and audience and throws `InvalidRequest` on failure. See [IdToken](/reference/id-token/).

## Key rotation duties

The library signs with the key you give it and publishes the keys you list. Rotation is a host procedure.

1. Persist signing keys. Generate with `extractable: true` and store the exported JWK, or use a key held in a KMS.
2. Publish the next key in `Keys.jwks` before you sign with it. Wait at least the JWKS cache time of your clients and resource servers.
3. Switch the `TokenSigner` to the new `kid`.
4. Keep the retired public key in the JWK Set until the last token it signed has expired.

```ts
import { Keys } from 'oidc-primitive';
import { exportJWK, importJWK } from 'jose';

const next = await Keys.generate('ES256', { extractable: true });
const stored = await exportJWK(next.privateKey);
const restored = (await importJWK(stored, 'ES256')) as CryptoKey;

declare const retiredPublicKey: CryptoKey;
const jwks = await Keys.jwks([
	{ key: next.publicKey, kid: 'op-2', alg: 'ES256' },
	{ key: retiredPublicKey, kid: 'op-1', alg: 'ES256' },
]);
```

Access tokens are JWTs. A resource server accepts one until `exp` even after you revoke the grant, so keep lifetimes short.

Verification accepts only `ES256`, `EdDSA`, `PS256` and `RS256` (`Keys.tokenAlgorithms`).

## Host duties here

- Persist and rotate signing keys.
- Choose token lifetimes.
- Store refresh tokens as `OpaqueToken.hash` and rotate them with compare-and-swap.

See the [Host checklist](/guide/host-checklist/).
