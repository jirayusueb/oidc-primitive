---
title: IdToken
description: Sign ID tokens with azp and at_hash, and verify an id_token_hint.
---

`IdToken` signs ID tokens and verifies them when a client sends one back as `id_token_hint`. It follows [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) section 2 (claims), section 3.1.3.6 (`at_hash`) and section 3.1.2.1 (`id_token_hint`). Bind a key once with [TokenSigner](/reference/token-signer/).

## Import

```ts
import { IdToken } from 'oidc-primitive';
```

## Claims

Input claims for `sign`. The library owns `iss`, `iat` and `exp`.

```ts title="signature"
interface Claims {
  readonly sub: string;
  readonly aud: string | string[];
  readonly nonce?: string;
  readonly auth_time?: number;
  readonly acr?: string;
  readonly amr?: string[];
  readonly iss?: never;
  readonly iat?: never;
  readonly exp?: never;
  readonly [claim: string]: unknown;
}
```

## SignOptions

```ts title="signature"
interface SignOptions {
  readonly issuer: string;
  readonly key: CryptoKey;
  readonly kid: string;
  readonly alg: string;
  readonly clientId?: string;
  readonly expiresIn?: string | number;
  readonly accessToken?: string | Redacted<string>;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Becomes `iss`. |
| `key` | `CryptoKey` | none | Private signing key. |
| `kid` | `string` | none | Written to the protected header. |
| `alg` | `string` | none | Written to the protected header. |
| `clientId` | `string` | none | Required when `aud` has several values. Becomes `azp`. |
| `expiresIn` | `string \| number` | `600` | A number is seconds from now. A string is a jose time span such as `"10m"`. |
| `accessToken` | `string \| Redacted<string>` | none | Adds `at_hash` for the access token issued with this ID token. |

## sign

```ts title="signature"
const sign: (claims: Claims, options: SignOptions) => Promise<string>;
```

Returns the compact JWT. Sets `iss`, `iat`, `exp`, and `azp` and `at_hash` when applicable.

Throws `TypeError` when `aud` has several values and `clientId` is missing or not contained in `aud`. Throws `TypeError` from `atHash` for an unsupported `alg`.

```ts
const jwt = await IdToken.sign(
  { sub: 'user-1', aud: 'client-1', nonce: 'n-0S6_WzA2Mj' },
  { issuer: 'https://op.example.com', key: privateKey, kid: 'k1', alg: 'ES256', accessToken: 'opaque-access-token' },
);
```

## atHash

```ts title="signature"
const atHash: (accessToken: string | Redacted<string>, alg: string) => Promise<string>;
```

Returns the left half of the access token's hash, base64url. The hash size follows `alg`: `ES256`, `RS256` and `PS256` use SHA-256, the `384` variants SHA-384, the `512` variants SHA-512, and `EdDSA` SHA-512. Throws `TypeError` (`no at_hash hash for algorithm "<alg>"`) for any other `alg`.

```ts
const value = await IdToken.atHash('opaque-access-token', 'ES256');
```

## VerifyOptions

```ts title="signature"
interface VerifyOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly keys: VerifyKey;
  readonly allowExpired?: boolean;
  readonly algorithms?: readonly string[];
  readonly clockTolerance?: number;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Required `iss`. |
| `audience` | `string` | none | Required `aud` value. |
| `keys` | [`Keys.VerifyKey`](/reference/keys/#verifykey) | none | Public key, JWK or resolver. |
| `allowExpired` | `boolean` | `false` | Accept an expired token. Signature, issuer and audience still apply. |
| `algorithms` | `readonly string[]` | `Keys.tokenAlgorithms` | Narrows the allow-list. A value outside it throws `TypeError`. |
| `clockTolerance` | `number` | `30` | Seconds of clock skew. |

## VerifiedClaims

```ts title="signature"
interface VerifiedClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | string[];
  readonly iat: number;
  readonly exp: number;
  readonly [claim: string]: unknown;
}
```

The claims every verified ID token carries. Other claims pass through.

## verify

```ts title="signature"
const verify: (jwt: string, options: VerifyOptions) => Promise<VerifiedClaims>;
```

Verifies an ID token for use as `id_token_hint`. Requires `sub`, `iat` and `exp`, and checks that `iss` and `sub` are strings and `iat` and `exp` are numbers. Returns the typed claims. With `allowExpired`, an expired but authentic token returns its claims.

Throws `OAuthError.InvalidRequest` (`id_token_hint is invalid`) on any failure. Throws `TypeError` when `algorithms` leaves the allow-list.

```ts
const hint = await IdToken.verify(jwt, {
  issuer: 'https://op.example.com',
  audience: 'client-1',
  keys: publicKey,
  allowExpired: true,
});
console.log(hint.sub);
```

## Spec

- [OIDC Core section 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): `azp` and ID token claims.
- [OIDC Core section 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest): `id_token_hint`.
- [OIDC Core section 3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken): `at_hash`. The tests use the OIDC Core Appendix A.3 vector.
