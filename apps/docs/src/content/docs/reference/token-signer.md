---
title: TokenSigner
description: Bind a signing key to an issuer once and sign ID tokens and access tokens with it.
---

`TokenSigner` fixes `issuer`, `key`, `kid` and `alg`, then signs with [IdToken.sign](/reference/id-token/#sign) and [AccessToken.sign](/reference/access-token/#sign). Per-client values such as `clientId` and `accessToken` stay per call. Bound values win over per-call values of the same name. See [tokens and keys](/guide/tokens-and-keys/).

## Import

```ts
import { TokenSigner } from 'oidc-primitive';
```

## Options

```ts title="signature"
interface Options {
  readonly issuer: string;
  readonly key: CryptoKey;
  readonly kid: string;
  readonly alg: string;
}
```

## TokenSigner

```ts title="signature"
class TokenSigner {
  constructor(options: Options);
  idToken(claims: IdToken.Claims, perCall?: Omit<IdToken.SignOptions, 'issuer' | 'key' | 'kid' | 'alg'>): Promise<string>;
  accessToken(claims: AccessToken.Claims, perCall?: Omit<AccessToken.SignOptions, 'issuer' | 'key' | 'kid' | 'alg'>): Promise<string>;
}
```

### idToken

Calls `IdToken.sign`. `perCall` may set `clientId`, `expiresIn` and `accessToken`. Throws what `IdToken.sign` throws.

### accessToken

Calls `AccessToken.sign`. `perCall` may set `expiresIn`.

## make

```ts title="signature"
const make: (options: Options) => TokenSigner;
```

Same as `new TokenSigner(options)`.

```ts
const signer = TokenSigner.make({
  issuer: 'https://op.example.com',
  key: privateKey,
  kid: 'k1',
  alg: 'ES256',
});

const accessToken = await signer.accessToken(
  { sub: 'user-1', aud: 'https://api.example.com', client_id: 'client-1', scope: 'read' },
  { expiresIn: '5m' },
);
const idToken = await signer.idToken(
  { sub: 'user-1', aud: 'client-1' },
  { accessToken },
);
```

## Spec

- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): access token signing.
- [OIDC Core section 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): ID token claims and `azp`.
