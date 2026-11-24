---
title: Client authentication
description: Authenticate clients at the token endpoint with client secrets or signed client assertions.
---

At the token endpoint the client proves who it is. The library parses and checks the credential. The host looks up the client and decides which method that client may use.

## Store secrets as hashes

[Token](/reference/token/) generates and hashes opaque credentials. When you issue a client secret, show it once and store only `Token.hash(secret)` ([RFC 6749 s10.10](https://www.rfc-editor.org/rfc/rfc6749#section-10.10)).

```ts
import { Redacted, Token } from 'oidc-primitive';

const secret = Token.generate();
const secretHash: string = await Token.hash(secret);
const shownOnce: string = Redacted.value(secret);
```

## client_secret_basic and client_secret_post

`ClientSecret.parseBasic` reads an `Authorization: Basic` header ([RFC 6749 s2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1)). It returns `undefined` when the header is absent or uses another scheme. It throws `InvalidClient` when the header is malformed. The secret comes back as `Redacted<string>`.

`Token.matchesHash` compares the presented secret to the stored hash in constant time.

```ts
import { OAuthError, ClientSecret, Redacted, Token } from 'oidc-primitive';

declare const request: Request;
declare const form: URLSearchParams;
declare const findClient: (id: string) => Promise<{ secretHash: string } | undefined>;

const basic = ClientSecret.parseBasic(request.headers.get('authorization'));
const clientId = basic?.clientId ?? form.get('client_id') ?? '';
const secret = basic ? Redacted.value(basic.clientSecret) : form.get('client_secret');
const client = await findClient(clientId);
if (!client || secret === null || !(await Token.matchesHash(secret, client.secretHash))) {
	throw new OAuthError.InvalidClient('client authentication failed');
}
```

Use one message for an unknown client and a wrong secret. The host must also enforce that the client used the method it registered. The [Example OP](/guide/example-op/) shows this in its `authenticate` function. See [ClientSecret](/reference/client-secret/).

## private_key_jwt

The client sends `client_assertion_type` and `client_assertion` in the form body. Check the type against `ClientAssertion.assertionType`, then call `ClientAssertion.verify` with the issuer, the client id and the client's public keys.

`keys` is a `CryptoKey` or a jose key resolver. [Keys](/reference/keys/) builds resolvers: `Keys.localSet` for a JWK Set you store, `Keys.remoteSet` for a client `jwks_uri`.

```ts
import { ClientAssertion, Keys, OAuthError } from 'oidc-primitive';

declare const form: URLSearchParams;
declare const issuer: string;
declare const clientId: string;
declare const clientJwks: { keys: import('jose').JWK[] };
declare const rememberJti: (jti: string, expiresAt: number) => Promise<boolean>;

if (form.get('client_assertion_type') !== ClientAssertion.assertionType) {
	throw new OAuthError.InvalidClient('unsupported client assertion type');
}
const { jti, expiresAt } = await ClientAssertion.verify(form.get('client_assertion') ?? '', {
	issuer,
	clientId,
	keys: Keys.localSet(clientJwks),
});
if (!(await rememberJti(jti, expiresAt))) {
	throw new OAuthError.InvalidClient('Client assertion is invalid');
}
```

The check enforces `iss` and `sub` equal to the client id, `aud` exactly the issuer identifier ([RFC 7523 s3](https://www.rfc-editor.org/rfc/rfc7523#section-3), RFC 10070 s4), and `exp`, `jti` present. Defaults: `clockTolerance` is 30 seconds, `maxLifetime` is 600 seconds. Every failure throws `InvalidClient`. A key fetch failure throws `TemporarilyUnavailable`.

### Replay is the host's duty

The library keeps no state. `ClientAssertion.verify` returns `jti` and `expiresAt` (epoch seconds). Record the `jti` until `expiresAt`. Reject a `jti` you have seen before. `rememberJti` above is your insert-if-absent operation. See [ClientAssertion](/reference/client-assertion/).

Advertise the methods you accept in [discovery metadata](/guide/discovery-and-responses/).

## Host duties here

- Look up the client and require the registered authentication method.
- Rate-limit failed authentication per `client_id` and IP.
- Record assertion `jti` values until they expire.
- Store secrets only as `Token.hash`.

See the [Host checklist](/guide/host-checklist/).
