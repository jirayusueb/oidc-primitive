---
title: Resource
description: Validate RFC 8707 resource indicators and pick the single access token audience.
---

`Resource` handles the `resource` request parameter of [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707). One access token serves one audience, so more than one distinct resource is rejected ([RFC 9700 section 2.3](https://www.rfc-editor.org/rfc/rfc9700#section-2.3)). Failures are `OAuthError.InvalidTarget`.

## Import

```ts
import { Resource } from 'oidc-primitive';
```

## validate

```ts title="signature"
const validate: (uri: string) => void;
```

Returns nothing when `uri` is an absolute URI without a fragment ([RFC 8707 section 2](https://www.rfc-editor.org/rfc/rfc8707#section-2)). Throws `OAuthError.InvalidTarget` (`resource must be an absolute URI without a fragment`) otherwise.

## resolveAudience

```ts title="signature"
const resolveAudience: (resources: ReadonlyArray<string>, issuer: string) => string;
```

Returns the access token audience for the requested resources:

- none sent: `issuer`;
- one distinct value (duplicates collapse): that value, after `validate`;
- several distinct values: throws `OAuthError.InvalidTarget` (`only one resource is supported per request`).

```ts
const params = new URL(request.url).searchParams;
const aud = Resource.resolveAudience(params.getAll('resource'), 'https://op.example.com');
```

## Spec

- [RFC 8707 section 2](https://www.rfc-editor.org/rfc/rfc8707#section-2): the `resource` parameter.
- [RFC 9700 section 2.3](https://www.rfc-editor.org/rfc/rfc9700#section-2.3): audience restriction.
