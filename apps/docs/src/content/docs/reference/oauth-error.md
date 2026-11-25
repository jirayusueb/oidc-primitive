---
title: OAuthError
description: One error class per OAuth error code, each able to render its own HTTP response or redirect.
---

`OAuthError` is the base class and the namespace for every protocol error the library throws. Each error knows its `error` code, HTTP status and response shape ([RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2), [section 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1), [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)). Catch one at the edge of your handler and call `toResponse()`.

## Import

```ts
import { OAuthError } from 'oidc-primitive';
```

The namespace contains the class of the same name: use `OAuthError.OAuthError` for `instanceof` checks.

## Code

```ts title="signature"
type Code =
  | 'invalid_redirect_uri' | 'invalid_request' | 'invalid_client' | 'invalid_grant' | 'unauthorized_client'
  | 'unsupported_grant_type' | 'unsupported_response_type' | 'invalid_scope' | 'invalid_target'
  | 'access_denied' | 'login_required' | 'consent_required' | 'interaction_required'
  | 'account_selection_required' | 'request_not_supported' | 'request_uri_not_supported'
  | 'registration_not_supported' | 'invalid_token' | 'insufficient_scope'
  | 'server_error' | 'temporarily_unavailable';
```

## Options

```ts title="signature"
interface Options {
  readonly status?: number;
  readonly description?: string;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `status` | `number` | `400` | HTTP status of `toResponse()`. |
| `description` | `string` | none | Sent as `error_description`. |

## RedirectOptions

```ts title="signature"
interface RedirectOptions {
  readonly state?: string;
  readonly issuer: string;
}
```

## OAuthError

```ts title="signature"
class OAuthError extends Error {
  readonly _tag: string;
  readonly code: string;
  readonly status: number;
  readonly description: string | undefined;
  constructor(code: string, options?: Options);
  toJSON(): { error?: string; error_description?: string };
  toResponse(): Response;
  toRedirect(redirectUri: string, options: RedirectOptions): Response;
}
```

`description` is sent to the client. Never put request input, tokens or secrets in it.

| Member | Meaning |
| --- | --- |
| `_tag` | The subclass name, for example `'InvalidGrant'`. Use it to discriminate. |
| `code` | The `error` value. |
| `status` | HTTP status. |
| `toJSON()` | `{ error, error_description? }`. |
| `toResponse()` | A JSON response with `Cache-Control: no-store` and the error's status. |
| `toRedirect(redirectUri, { state, issuer })` | A 303 redirect with `error`, `error_description`, `state` and `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)) in the query. Use it only after the redirect URI is verified. |

`toRedirect` throws `TypeError` when `redirectUri` is not an absolute URL.

```ts
try {
  throw new OAuthError.InvalidGrant('authorization code is expired');
} catch (error) {
  if (error instanceof OAuthError.OAuthError) return error.toResponse();
  throw error;
}
```

```ts
const redirect = new OAuthError.AccessDenied('the user denied the request').toRedirect(
  'https://client.example.com/cb',
  { state: 'xyz', issuer: 'https://op.example.com' },
);
```

## Error classes

Every class extends `OAuthError`. Constructors take an optional `description` unless noted.

| Class | `error` | Status |
| --- | --- | --- |
| `InvalidRequest` | `invalid_request` | 400 |
| `InvalidRedirectUri` | `invalid_redirect_uri` | 400 |
| `InvalidClient` | `invalid_client` | 401 |
| `InvalidGrant` | `invalid_grant` | 400 |
| `UnauthorizedClient` | `unauthorized_client` | 400 |
| `UnsupportedGrantType` | `unsupported_grant_type` | 400 |
| `UnsupportedResponseType` | `unsupported_response_type` | 400 |
| `InvalidScope` | `invalid_scope` | 400 |
| `InvalidTarget` | `invalid_target` | 400 |
| `AccessDenied` | `access_denied` | 403 |
| `LoginRequired` | `login_required` | 400 |
| `ConsentRequired` | `consent_required` | 400 |
| `InteractionRequired` | `interaction_required` | 400 |
| `AccountSelectionRequired` | `account_selection_required` | 400 |
| `RequestNotSupported` | `request_not_supported` | 400 |
| `RequestUriNotSupported` | `request_uri_not_supported` | 400 |
| `RegistrationNotSupported` | `registration_not_supported` | 400 |
| `MissingToken` | `invalid_token` | 401 |
| `InvalidToken` | `invalid_token` | 401 |
| `InsufficientScope` | `insufficient_scope` | 403 |
| `ServerError` | `server_error` | 500 |
| `TemporarilyUnavailable` | `temporarily_unavailable` | 503 |

The status applies to `toResponse()`. A redirect from `toRedirect()` is always 303.

## InvalidClient

```ts title="signature"
class InvalidClient extends OAuthError {
  readonly scheme: 'Basic' | undefined;
  constructor(description?: string, options?: { readonly scheme?: 'Basic' });
}
```

Pass `{ scheme: 'Basic' }` when the client authenticated with the `Authorization` header. Then `toResponse()` adds `WWW-Authenticate: Basic realm="token"` (RFC 6749 section 5.2). Without it, there is no header.

## MissingToken

```ts title="signature"
class MissingToken extends OAuthError {
  constructor();
}
```

For a request with no bearer token at all. `toResponse()` returns 401 with an empty body and a bare `WWW-Authenticate: Bearer` header, with no error code ([RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)). `toJSON()` returns `{}`. `toRedirect()` throws `TypeError`, because a missing token is a resource-server condition. It is not an `InvalidToken`, so catch `OAuthError` to handle both.

## InvalidToken

`toResponse()` returns the JSON body plus a `WWW-Authenticate: Bearer error="invalid_token"` header. `error_description` is added to the header only when it has no characters outside [RFC 6750 section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3). Otherwise it is dropped from the header and stays in the body.

## InsufficientScope

```ts title="signature"
class InsufficientScope extends OAuthError {
  readonly scope: string | undefined;
  constructor(scope?: string, description?: string);
}
```

The first argument is the space-delimited scope the request needed. `toResponse()` puts it in the Bearer challenge as `scope`.

```ts
return new OAuthError.InsufficientScope('write').toResponse();
```

## fromCode

```ts title="signature"
const fromCode: (code: Code | (string & {}), options?: Options) => OAuthError;
```

Builds an `OAuthError`. A registered `Code` returns its subclass, with the status and challenge the RFC defines, and ignores `options.status`. Any other code, for extension specs such as `use_dpop_nonce`, returns a base `OAuthError` that honors `options`.

```ts
const error = OAuthError.fromCode('use_dpop_nonce', { status: 401 });
```

## Spec

- [RFC 6749 section 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1): authorization error response.
- [RFC 6749 section 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2): token error response.
- [RFC 6750 section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3) and [section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1): Bearer challenges.
- [RFC 9207 section 2](https://www.rfc-editor.org/rfc/rfc9207#section-2): `iss` in the redirect.
- [RFC 8707 section 2](https://www.rfc-editor.org/rfc/rfc8707#section-2): `invalid_target`.
- [OIDC Core section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError): `login_required`, `consent_required` and related codes.
