---
title: ClientSecret
description: Parse HTTP Basic client credentials for client_secret_basic and wrap the secret so it cannot be logged.
---

`ClientSecret` parses `Authorization: Basic` credentials as [RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) defines them: base64 of `client_id:client_secret`, with each half form-urlencoded. The secret comes back as [Redacted](/reference/redacted/). Compare it to the stored hash with [`OpaqueToken.matchesHash`](/reference/opaque-token/#matcheshash). See [client authentication](/guide/client-authentication/).

## Import

```ts
import { ClientSecret } from 'oidc-primitive';
```

## BasicCredentials

```ts title="signature"
interface BasicCredentials {
  readonly clientId: string;
  readonly clientSecret: Redacted<string>;
}
```

## parseBasic

```ts title="signature"
const parseBasic: (header: string | null | undefined) => BasicCredentials | undefined;
```

| Result | When |
| --- | --- |
| `BasicCredentials` | A valid Basic credential. Both halves are form-decoded. |
| `undefined` | The header is absent or empty, or uses another scheme. |
| throws `OAuthError.InvalidClient` | The scheme is `Basic` but the value is malformed (`malformed Basic credentials`). |

Malformed means: a missing token, extra tokens, invalid base64, invalid UTF-8, no colon, an empty client id, or invalid percent-encoding. The scheme match is case-insensitive.

```ts
const creds = ClientSecret.parseBasic(request.headers.get('authorization'));
if (creds !== undefined) {
  const ok = await OpaqueToken.matchesHash(creds.clientSecret, 'stored-hash');
  console.log(creds.clientId, ok);
}
```

## Spec

- [RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1): client password authentication.
- [RFC 6749 Appendix B](https://www.rfc-editor.org/rfc/rfc6749#appendix-B): `application/x-www-form-urlencoded` encoding.
