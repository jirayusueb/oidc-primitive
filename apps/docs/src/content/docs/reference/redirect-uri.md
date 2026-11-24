---
title: RedirectUri
description: Validate redirect URIs at registration and match them exactly at request time.
---

`RedirectUri` enforces the redirect URI rules of [RFC 6749 section 3.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2), [RFC 8252 section 7](https://www.rfc-editor.org/rfc/rfc8252#section-7) and [RFC 9700 section 4.1.3](https://www.rfc-editor.org/rfc/rfc9700#section-4.1.3). Call `validate` when a client registers. Call `match` on every authorization request. See [authorization requests](/guide/authorization-requests/).

## Import

```ts
import { RedirectUri } from 'oidc-primitive';
```

## ApplicationType

```ts title="signature"
type ApplicationType = 'web' | 'native';
```

## validate

```ts title="signature"
const validate: (
  uri: string,
  options?: { readonly applicationType?: ApplicationType },
) => void;
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `applicationType` | `ApplicationType` | `'web'` | `'native'` allows private-use schemes. |

Returns nothing when the URI is acceptable. Throws `OAuthError.InvalidRequest` when:

- it is not an absolute URI (`redirect_uri is not an absolute URI`);
- it contains a fragment (`redirect_uri must not contain a fragment`);
- it uses `http` on a host other than `localhost`, `127.0.0.1` or `[::1]` (`redirect_uri must use https outside loopback`);
- it uses another scheme, and either the type is `web`, or the scheme is `javascript:`, `data:`, `vbscript:`, `file:` or `blob:` (`redirect_uri scheme is not allowed`).

`https` URIs always pass.

```ts
RedirectUri.validate('https://client.example.com/cb');
RedirectUri.validate('com.example.app:/oauth2redirect', { applicationType: 'native' });
```

## match

```ts title="signature"
const match: (requested: string, registered: ReadonlyArray<string>) => string | undefined;
```

Compares by exact string ([RFC 9700 section 4.1.3](https://www.rfc-editor.org/rfc/rfc9700#section-4.1.3)). One exception: for `http://127.0.0.1` and `http://[::1]` the port may differ ([RFC 8252 section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)). The host must be the same loopback literal, and everything else must be equal. `localhost` gets no port flexibility.

Returns the registered URI that matched, or `undefined`.

```ts
const registered = ['https://client.example.com/cb', 'http://127.0.0.1/cb'];
const uri = RedirectUri.match('http://127.0.0.1:51234/cb', registered);
```

## matches

```ts title="signature"
const matches: (requested: string, registered: ReadonlyArray<string>) => boolean;
```

True when `match` finds a registered URI.

```ts
if (!RedirectUri.matches('https://evil.example.com/cb', ['https://client.example.com/cb'])) {
  throw new OAuthError.InvalidRequest('redirect_uri is not registered');
}
```

An unmatched redirect URI must not be redirected to. Show the error to the user instead.

## Spec

- [RFC 6749 section 3.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2): no fragment.
- [RFC 8252 section 7](https://www.rfc-editor.org/rfc/rfc8252#section-7): native app URIs, including section 7.1 private-use schemes and section 7.3 loopback ports.
- [RFC 9700 section 2.6](https://www.rfc-editor.org/rfc/rfc9700#section-2.6): `http` only on loopback.
- [RFC 9700 section 4.1.3](https://www.rfc-editor.org/rfc/rfc9700#section-4.1.3): exact matching.
