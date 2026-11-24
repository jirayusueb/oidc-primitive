---
title: ResourceMetadata
description: Build RFC 9728 protected resource metadata and its well-known URL.
---

`ResourceMetadata` builds the document a resource server publishes so clients can find its authorization servers ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)). Point the `resource_metadata` parameter of your [Bearer](/reference/bearer/#challenge) challenge at its URL. See the [resource server guide](/guide/resource-servers/).

## Import

```ts
import { ResourceMetadata } from 'oidc-primitive';
```

## Options

```ts title="signature"
interface Options {
  readonly resource: string;
  readonly authorizationServers: readonly string[];
  readonly scopesSupported?: readonly string[];
  readonly bearerMethodsSupported?: readonly string[];
  readonly resourceName?: string;
  readonly jwksUri?: string;
  readonly resourceSigningAlgValuesSupported?: readonly string[];
  readonly resourceDocumentation?: string;
}
```

| Option | Type | Default | Document member |
| --- | --- | --- | --- |
| `resource` | `string` | none | `resource` |
| `authorizationServers` | `readonly string[]` | none, must not be empty | `authorization_servers` |
| `scopesSupported` | `readonly string[]` | omitted | `scopes_supported` |
| `bearerMethodsSupported` | `readonly string[]` | `['header']` | `bearer_methods_supported` |
| `resourceName` | `string` | omitted | `resource_name` |
| `jwksUri` | `string` | omitted | `jwks_uri` |
| `resourceSigningAlgValuesSupported` | `readonly string[]` | omitted | `resource_signing_alg_values_supported` |
| `resourceDocumentation` | `string` | omitted | `resource_documentation` |

## make

```ts title="signature"
const make: (options: Options) => Record<string, unknown>;
```

Returns the document in snake_case. Members whose value is `undefined` are removed.

Throws `TypeError` when `resource` is not an absolute URL, is not `https`, or has a fragment ([RFC 9728 section 2](https://www.rfc-editor.org/rfc/rfc9728#section-2)), or when `authorizationServers` is empty.

```ts
const document = ResourceMetadata.make({
  resource: 'https://api.example.com',
  authorizationServers: ['https://op.example.com'],
  scopesSupported: ['read', 'write'],
});
return Response.json(document);
```

## wellKnownUrl

```ts title="signature"
const wellKnownUrl: (resource: string) => string;
```

Returns the metadata URL. `/.well-known/oauth-protected-resource` goes between the origin and the resource's path and query ([RFC 9728 section 3.1](https://www.rfc-editor.org/rfc/rfc9728#section-3.1)). A trailing slash on the path is removed. Throws `TypeError` for the same `resource` problems as `make`.

```ts
const url = ResourceMetadata.wellKnownUrl('https://api.example.com/v1');
// https://api.example.com/.well-known/oauth-protected-resource/v1
```

## Spec

- [RFC 9728 section 2](https://www.rfc-editor.org/rfc/rfc9728#section-2): resource metadata.
- [RFC 9728 section 3.1](https://www.rfc-editor.org/rfc/rfc9728#section-3.1): well-known URL.
- [RFC 9728 section 5.1](https://www.rfc-editor.org/rfc/rfc9728#section-5.1): `resource_metadata` in the challenge.
