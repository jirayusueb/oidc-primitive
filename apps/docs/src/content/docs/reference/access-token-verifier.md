---
title: AccessTokenVerifier
description: A resource-server verifier that binds AccessToken.verify to one issuer, audience and key source.
---

`AccessTokenVerifier` wraps [AccessToken](/reference/access-token/) with fixed `issuer`, `audience` and `keys`, reads the token from the `Authorization` header with [Bearer](/reference/bearer/), and splits the token's scopes into the ones your API declares. It follows [RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4) and [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1). See the [resource server guide](/guide/resource-servers/).

## Import

```ts
import { AccessTokenVerifier } from 'oidc-primitive';
```

## Options

```ts title="signature"
interface Options<S extends string = string> {
  readonly issuer: string;
  readonly audience: string;
  readonly keys: VerifyKey;
  readonly scopes?: readonly S[];
  readonly clockTolerance?: number;
  readonly confirm?: AccessToken.VerifyOptions['confirm'];
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Required `iss`. |
| `audience` | `string` | none | Required `aud`. |
| `keys` | [`Keys.VerifyKey`](/reference/keys/#verifykey) | none | Public key, JWK or resolver. |
| `scopes` | `readonly S[]` | `[]` | Scopes this resource server knows. Others in a token are ignored, not rejected. |
| `clockTolerance` | `number` | `30` | Seconds of clock skew. |
| `confirm` | function | none | The `cnf` hook from [`AccessToken.VerifyOptions`](/reference/access-token/#verifyoptions). |

## Verified

```ts title="signature"
interface Verified<S extends string = string> {
  readonly claims: AccessToken.VerifiedClaims;
  /** Every scope in the token. */
  readonly scope: string[];
  /** Declared scopes present in the token. */
  readonly granted: S[];
}
```

## AccessTokenVerifier

```ts title="signature"
class AccessTokenVerifier<S extends string = string> {
  constructor(options: Options<S>);
  verify(token: string): Promise<Verified<S>>;
  verifyRequest(headers: Headers): Promise<Verified<S>>;
}
```

### verify

Runs `AccessToken.verify` with the bound options, then parses the `scope` claim.

Throws every error `AccessToken.verify` throws, plus `OAuthError.InvalidToken` (`token is invalid`) when `scope` is malformed.

### verifyRequest

Calls `Bearer.extract(headers)` and then `verify`. Throws `OAuthError.MissingToken` when there is no Bearer credential (RFC 6750 section 3.1). Throws `OAuthError.InvalidToken` when the credential is malformed.

## make

```ts title="signature"
const make: <const S extends string = string>(options: Options<S>) => AccessTokenVerifier<S>;
```

Same as `new AccessTokenVerifier(options)`. The `const` parameter keeps the literal scope names, so `granted` is typed from `scopes`.

```ts
const verifier = AccessTokenVerifier.make({
  issuer: 'https://op.example.com',
  audience: 'https://api.example.com',
  keys: Keys.remoteSet('https://op.example.com/jwks'),
  scopes: ['read', 'write'],
});

try {
  const { claims, granted } = await verifier.verifyRequest(request.headers);
  console.log(claims.sub, granted);
} catch (error) {
  if (error instanceof OAuthError.OAuthError) return error.toResponse();
  throw error;
}
```

## Spec

- [RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4): resource server verification.
- [RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1): `verifyRequest` reads the `Authorization` header.
- [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1): a missing credential gets a bare `Bearer` challenge.
- [RFC 9449 section 7.1](https://www.rfc-editor.org/rfc/rfc9449#section-7.1): `confirm` passes through.
