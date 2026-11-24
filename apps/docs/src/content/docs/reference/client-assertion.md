---
title: ClientAssertion
description: Verify a private_key_jwt client assertion and return the jti the host must record against replay.
---

`ClientAssertion` verifies a JWT client assertion for `private_key_jwt` authentication ([RFC 7523 section 3](https://www.rfc-editor.org/rfc/rfc7523#section-3), [RFC 7521 section 4.2](https://www.rfc-editor.org/rfc/rfc7521#section-4.2)). The audience must be exactly the issuer identifier. The library does not store `jti` values. Replay checking stays with the host. See [client authentication](/guide/client-authentication/).

## Import

```ts
import { ClientAssertion } from 'oidc-primitive';
```

## assertionType

```ts title="signature"
const assertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
```

The expected `client_assertion_type` request parameter value. Compare it yourself before calling `verify`.

## algorithms

```ts title="signature"
const algorithms: readonly string[];
```

Accepted signing algorithms: `ES256`, `EdDSA`, `PS256`, `RS256`, `ES384`, `ES512`, `PS384`, `PS512`, `RS384`, `RS512`. `HS*` and `none` are never accepted.

## VerifyOptions

```ts title="signature"
interface VerifyOptions {
  readonly issuer: string;
  readonly clientId: string;
  readonly keys: CryptoKey | JWTVerifyGetKey;
  readonly clockTolerance?: number;
  readonly maxLifetime?: number;
  readonly currentDate?: Date;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | `string` | none | Your issuer identifier. Required `aud`. |
| `clientId` | `string` | none | Required `iss` and `sub`. |
| `keys` | `CryptoKey \| JWTVerifyGetKey` | none | The client's public key, or a resolver such as `Keys.localSet` or `Keys.remoteSet`. |
| `clockTolerance` | `number` | `30` | Seconds of clock skew. |
| `maxLifetime` | `number` | `600` | Maximum seconds `exp` may lie ahead of now. |
| `currentDate` | `Date` | now | Clock override, for tests. |

## Verified

```ts title="signature"
interface Verified {
  readonly jti: string;
  /** Epoch seconds; keep the `jti` until then to reject replays. */
  readonly expiresAt: number;
}
```

## verify

```ts title="signature"
const verify: (jwt: string, options: VerifyOptions) => Promise<Verified>;
```

Requires `iss`, `sub`, `aud`, `exp` and `jti`. `iss` and `sub` must equal `clientId`. `aud` must be the issuer string, or a one-element array holding it. `jti` must be a non-empty string.

| Throws | When |
| --- | --- |
| `OAuthError.InvalidClient` | Any check fails (`Client assertion is invalid`). The reason is not revealed. |
| `OAuthError.TemporarilyUnavailable` | The client's keys could not be fetched (HTTP 503). |

```ts
const { jti, expiresAt } = await ClientAssertion.verify(jwt, {
  issuer: 'https://op.example.com',
  clientId: 'client-1',
  keys: Keys.remoteSet('https://client.example.com/jwks'),
});
// Store jti until expiresAt; reject the assertion if it was seen before.
console.log(jti, expiresAt);
```

## Spec

- [RFC 7523 section 3](https://www.rfc-editor.org/rfc/rfc7523#section-3): JWT assertion claims and processing.
- [RFC 7521 section 4.2](https://www.rfc-editor.org/rfc/rfc7521#section-4.2): `client_assertion_type`.
- The test suite also cites RFC 10070 section 4 for the audience rule.
