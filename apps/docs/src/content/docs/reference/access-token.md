---
title: AccessToken
description: Sign and verify RFC 9068 JWT access tokens, including the sender-constrained `cnf` hook.
---

`AccessToken` signs and verifies JWT access tokens in the [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) profile. `sign` sets `typ: at+jwt`, `iss`, `iat`, `exp` and `jti`. `verify` follows [RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4) and throws one error class for every bad token. A resource server usually calls this through [AccessTokenVerifier](/reference/access-token-verifier/).

## Import

```ts
import { AccessToken } from 'oidc-primitive';
```

## Claims

Input claims for `sign`. The library owns `iss`, `iat`, `exp` and `jti`, so the type forbids them.

```ts title="signature"
interface Claims {
  readonly sub: string;
  readonly aud: string | string[];
  readonly client_id: string;
  /** Space-delimited scopes (RFC 9068 s2.2.3). */
  readonly scope?: string;
  readonly cnf?: Record<string, unknown>;
  readonly iss?: never;
  readonly iat?: never;
  readonly exp?: never;
  readonly jti?: never;
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
  readonly expiresIn?: string | number;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Becomes `iss`. |
| `key` | `CryptoKey` | none | Private signing key. |
| `kid` | `string` | none | Written to the protected header. |
| `alg` | `string` | none | Written to the protected header. |
| `expiresIn` | `string \| number` | `"10m"` | A jose time span, or an absolute epoch-seconds number. |

## sign

```ts title="signature"
const sign: (claims: Claims, options: SignOptions) => Promise<string>;
```

Returns the compact JWT. The header carries `alg`, `kid` and `typ: at+jwt`. `jti` is `crypto.randomUUID()`.

```ts
const jwt = await AccessToken.sign(
  { sub: 'user-1', aud: 'https://api.example.com', client_id: 'client-1', scope: 'read write' },
  { issuer: 'https://op.example.com', key: privateKey, kid: 'k1', alg: 'ES256' },
);
```

## VerifyOptions

```ts title="signature"
interface VerifyOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly keys: VerifyKey;
  readonly algorithms?: readonly string[];
  readonly clockTolerance?: number;
  readonly confirm?: (cnf: Record<string, unknown>) => void | Promise<void>;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Required `iss`. |
| `audience` | `string` | none | Required `aud` value. |
| `keys` | [`Keys.VerifyKey`](/reference/keys/#verifykey) | none | A public key, a JWK, or a resolver from `Keys.localSet` or `Keys.remoteSet`. |
| `algorithms` | `readonly string[]` | `Keys.allowedAlgorithms` | Narrows the allow-list. A value outside `ES256`, `EdDSA`, `PS256`, `RS256` throws `TypeError`. |
| `clockTolerance` | `number` | `30` | Seconds of clock skew. |
| `confirm` | function | none | Called with `cnf` of a sender-constrained token. Throw to reject. Without it, such tokens are rejected. |

## VerifiedClaims

```ts title="signature"
interface VerifiedClaims extends JWTPayload {
  readonly iss: string;
  readonly sub: string;
  readonly client_id: string;
  readonly jti: string;
  readonly iat: number;
  readonly exp: number;
  readonly scope?: string;
  readonly cnf?: Record<string, unknown>;
}
```

## verify

```ts title="signature"
const verify: (token: string, options: VerifyOptions) => Promise<VerifiedClaims>;
```

Checks the signature, `typ: at+jwt`, `iss`, `aud` and `exp`. Requires `sub`, `client_id`, `jti`, `iat` and `exp`. Returns the verified payload.

| Throws | When |
| --- | --- |
| `TypeError` | `algorithms` contains a value outside the allow-list. |
| `OAuthError.TemporarilyUnavailable` | The key set could not be fetched (HTTP 503). |
| `OAuthError.InvalidToken` | The token is expired (`token expired`), fails any check (`token is invalid`), has a non-string `sub`, `jti`, `client_id` or `scope`, or has a `cnf` that is not a JSON object. |
| `OAuthError.InvalidToken` | The token has `cnf` and `confirm` is missing or throws a non-OAuth error (`token is sender-constrained`). |

An `OAuthError` thrown by `confirm` passes through unchanged. The error never echoes the token.

```ts
const claims = await AccessToken.verify(jwt, {
  issuer: 'https://op.example.com',
  audience: 'https://api.example.com',
  keys: publicKey,
  confirm: async (cnf) => {
    if (typeof cnf['jkt'] !== 'string') throw new Error('unsupported confirmation');
  },
});
```

## Spec

- [RFC 9068 section 2](https://www.rfc-editor.org/rfc/rfc9068#section-2): signing.
- [RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4): verification.
- [RFC 9449 section 7.1](https://www.rfc-editor.org/rfc/rfc9449#section-7.1): `cnf` confirmation.
- [RFC 7800 section 3.1](https://www.rfc-editor.org/rfc/rfc7800#section-3.1): `cnf` is a JSON object.
- [RFC 7519 section 4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1): string claims.
