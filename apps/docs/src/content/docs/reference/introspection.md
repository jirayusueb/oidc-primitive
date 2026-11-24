---
title: Introspection
description: Build RFC 7662 token introspection response bodies.
---

`Introspection` builds the response body for [RFC 7662 section 2.2](https://www.rfc-editor.org/rfc/rfc7662#section-2.2). A live token gets its claims plus `active: true`. Any other token gets only `active: false`. Client authentication and token lookup are the host's job.

## Import

```ts
import { Introspection } from 'oidc-primitive';
```

## Claims

```ts title="signature"
interface Claims {
  readonly scope?: string;
  readonly client_id?: string;
  readonly username?: string;
  readonly token_type?: string;
  readonly exp?: number;
  readonly iat?: number;
  readonly nbf?: number;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  readonly iss?: string;
  readonly jti?: string;
  readonly [claim: string]: unknown;
}
```

## active

```ts title="signature"
const active: (claims: Claims) => Record<string, unknown>;
```

Returns `claims` with `undefined` values dropped and `active: true` added. Extra claims pass through. A claim named `active` is overwritten, so it cannot be overridden.

## inactive

```ts title="signature"
const inactive: () => { active: false };
```

Returns `{ active: false }`. Use it for unknown, expired, revoked or foreign tokens so nothing else leaks.

## response

```ts title="signature"
const response: (body: Record<string, unknown>) => Response;
```

Returns a 200 JSON response with `Cache-Control: no-store`. It uses [`OAuthResponse.json`](/reference/oauth-response/#json).

```ts
const body = Introspection.active({
  scope: 'read write',
  client_id: 'client-1',
  sub: 'user-1',
  exp: 1893456000,
  token_type: 'Bearer',
});
return Introspection.response(body);
```

```ts
return Introspection.response(Introspection.inactive());
```

## Spec

- [RFC 7662 section 2.2](https://www.rfc-editor.org/rfc/rfc7662#section-2.2): introspection response.
