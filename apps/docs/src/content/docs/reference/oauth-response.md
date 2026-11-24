---
title: OAuthResponse
description: Build no-store JSON responses and RFC 9207 authorization redirects.
---

`OAuthResponse` builds the two response shapes an authorization server sends: JSON with `Cache-Control: no-store` ([RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)) and a 303 redirect that carries the issuer in `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). See [discovery and responses](/guide/discovery-and-responses/).

## Import

```ts
import { OAuthResponse } from 'oidc-primitive';
```

## JsonInit

```ts title="signature"
interface JsonInit {
  readonly status?: number;
  readonly headers?: HeadersInit;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `status` | `number` | `200` | HTTP status. |
| `headers` | `HeadersInit` | none | Extra headers. They override the defaults of the same name. |

## json

```ts title="signature"
const json: (body: unknown, init?: JsonInit) => Response;
```

Returns a JSON response. Default headers are `Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-store` and `Pragma: no-cache`. [Redacted](/reference/redacted/) values in `body` are unwrapped to their raw value, so a token you generated serializes as a real token.

```ts
const token = Token.generate();
return OAuthResponse.json({ access_token: token, token_type: 'Bearer', expires_in: 600 });
```

## redirect

```ts title="signature"
const redirect: (
  redirectUri: string,
  params: Record<string, string | number | Redacted<string> | undefined>,
  options: { readonly issuer: string },
) => Response;
```

Returns a 303 response. `Location` is `redirectUri` with `params` and `iss` set in the query. `undefined` params are skipped. `iss` always wins over a `params.iss`. Headers: `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Throws `TypeError` when `redirectUri` is not an absolute URL.

```ts
return OAuthResponse.redirect(
  'https://client.example.com/cb',
  { code: Token.generate(), state: 'xyz' },
  { issuer: 'https://op.example.com' },
);
```

## Spec

- [RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): successful token response headers.
- [RFC 9207 section 2](https://www.rfc-editor.org/rfc/rfc9207#section-2): `iss` in the authorization response.
