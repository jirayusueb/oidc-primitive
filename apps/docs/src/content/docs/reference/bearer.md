---
title: Bearer
description: Extract a bearer token from the Authorization header and build a WWW-Authenticate Bearer challenge.
---

`Bearer` implements the two parts of [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) a resource server needs. `extract` reads the credential from the `Authorization` header only. `challenge` formats the `WWW-Authenticate` value.

## Import

```ts
import { Bearer } from 'oidc-primitive';
```

## extract

```ts title="signature"
const extract: (headers: Headers) => string | undefined;
```

Reads the `Authorization` header. The query string and body are never read ([RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)). The scheme match is case-insensitive.

| Result | When |
| --- | --- |
| `string` | A well-formed `Bearer` credential. |
| `undefined` | No header, or another scheme. |
| throws `OAuthError.InvalidToken` | The scheme is `Bearer` but the token is not a valid `b64token` (`malformed bearer credential`). |

```ts
const token = Bearer.extract(request.headers);
```

## ChallengeOptions

```ts title="signature"
interface ChallengeOptions {
  readonly realm?: string;
  readonly error?: string;
  readonly errorDescription?: string;
  readonly scope?: string;
  readonly resourceMetadata?: string;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `realm` | `string` | omitted | `realm` auth-param. |
| `error` | `string` | omitted | An error code such as `invalid_token`. |
| `errorDescription` | `string` | omitted | Human-readable text. Written as `error_description`. |
| `scope` | `string` | omitted | Scopes required, for `insufficient_scope`. |
| `resourceMetadata` | `string` | omitted | URL of the protected resource metadata, written as `resource_metadata` ([RFC 9728 section 5.1](https://www.rfc-editor.org/rfc/rfc9728#section-5.1)). |

## challenge

```ts title="signature"
const challenge: (options?: ChallengeOptions) => string;
```

Returns a `WWW-Authenticate` value such as `Bearer realm="api", error="invalid_token"`. With no options it returns `Bearer`. Omitted options are left out.

Throws `TypeError` when a value has characters outside [RFC 6750 section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3).

```ts
const header = Bearer.challenge({
  realm: 'api',
  resourceMetadata: 'https://api.example.com/.well-known/oauth-protected-resource',
});
return new Response(null, { status: 401, headers: { 'WWW-Authenticate': header } });
```

[OAuthError](/reference/oauth-error/) builds these challenges for you in `toResponse`.

## Spec

- [RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1): Authorization request header field.
- [RFC 6750 section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3): `WWW-Authenticate` challenge.
- [RFC 9728 section 5.1](https://www.rfc-editor.org/rfc/rfc9728#section-5.1): `resource_metadata` parameter.
