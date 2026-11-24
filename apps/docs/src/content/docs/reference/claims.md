---
title: Claims
description: Map scopes to standard claims, parse the claims request parameter, and select the claims a response may carry.
---

`Claims` covers [OpenID Connect Core section 5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) (claims granted by scope) and [section 5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) (the `claims` request parameter). It decides which user attributes may leave the provider. Your host still loads the user and checks consent.

## Import

```ts
import { Claims } from 'oidc-primitive';
```

## Target

```ts title="signature"
type Target = 'userinfo' | 'id_token';
```

Where a claim will be returned.

## RequestMap

```ts title="signature"
type RequestMap = Readonly<Record<string, unknown>>;
```

Claim names requested for one target. Each value is `null` or an object, as in OIDC Core section 5.5.

## Request

```ts title="signature"
interface Request {
  readonly userinfo?: RequestMap;
  readonly id_token?: RequestMap;
}
```

The parsed `claims` parameter.

## forScopes

```ts title="signature"
const forScopes: (scopes: Iterable<string>) => string[];
```

Returns the standard claim names the scopes grant. Unknown scopes grant none. `openid` grants none.

| Scope | Claims |
| --- | --- |
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` |
| `phone` | `phone_number`, `phone_number_verified` |

```ts
const names = Claims.forScopes(['openid', 'email']);
```

## parseRequest

```ts title="signature"
const parseRequest: (json: string | null | undefined) => Request;
```

Parses the `claims` request parameter. `null` or `undefined` returns `{}`. Only `userinfo` and `id_token` members are kept.

Throws `OAuthError.InvalidRequest` when the value is not valid JSON (`claims parameter is not valid JSON`), is not a JSON object, or has a member that is neither `null` nor an object (`claims parameter is malformed`).

```ts
const raw = new URL(request.url).searchParams.get('claims');
const requested = Claims.parseRequest(raw);
```

## SelectOptions

```ts title="signature"
interface SelectOptions {
  readonly scopes: Iterable<string>;
  readonly request?: Request;
  readonly target: Target;
}
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `scopes` | `Iterable<string>` | none | Granted scopes. |
| `request` | `Request` | none | The parsed `claims` parameter. |
| `target` | `Target` | none | Which member of `request` applies. |

## select

```ts title="signature"
const select: (
  claims: Readonly<Record<string, unknown>>,
  options: SelectOptions,
) => Record<string, unknown>;
```

Returns only the entries of `claims` that a scope grants or that `request[target]` names. `sub` is always kept. Names with an `undefined` value are dropped.

```ts
const body = Claims.select(
  { sub: 'user-1', email: 'a@example.com', phone_number: '+1 555 0100' },
  { scopes: ['openid', 'email'], request: requested, target: 'userinfo' },
);
```

## Spec

- [OIDC Core section 5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims): claims requested by scope.
- [OIDC Core section 5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter): the `claims` request parameter.
