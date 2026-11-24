---
title: Metadata
description: Build the authorization server and OpenID Provider discovery document and its well-known URLs.
---

`Metadata` builds one document that serves both [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) authorization server metadata and [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) metadata, in snake_case. The values that describe what the library supports are fixed. See [discovery and responses](/guide/discovery-and-responses/).

## Import

```ts
import { Metadata } from 'oidc-primitive';
```

## Endpoints

```ts title="signature"
interface Endpoints {
  readonly authorization: string;
  readonly token: string;
  readonly jwks: string;
  readonly userinfo?: string;
  readonly introspection?: string;
  readonly revocation?: string;
  readonly registration?: string;
  readonly endSession?: string;
}
```

Absolute URLs. `authorization`, `token` and `jwks` are required.

## AuthorizationServerOptions

```ts title="signature"
interface AuthorizationServerOptions {
  readonly issuer: string;
  readonly endpoints: Endpoints;
  readonly scopes?: readonly string[];
  readonly grantTypes?: readonly string[];
  readonly tokenEndpointAuthMethods?: readonly string[];
  readonly tokenEndpointAuthSigningAlgs?: readonly string[];
  readonly idTokenSigningAlgs?: readonly string[];
  readonly claims?: readonly string[];
  readonly subjectTypes?: readonly string[];
  readonly claimsParameterSupported?: boolean;
}
```

| Option | Type | Default | Document member |
| --- | --- | --- | --- |
| `issuer` | `string` | none | `issuer` |
| `endpoints` | `Endpoints` | none | `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and the optional endpoints |
| `scopes` | `readonly string[]` | omitted | `scopes_supported` |
| `grantTypes` | `readonly string[]` | `['authorization_code', 'refresh_token']` | `grant_types_supported` |
| `tokenEndpointAuthMethods` | `readonly string[]` | `['client_secret_basic', 'client_secret_post', 'private_key_jwt']` | `token_endpoint_auth_methods_supported` |
| `tokenEndpointAuthSigningAlgs` | `readonly string[]` | `ES256`, `EdDSA`, `PS256`, `RS256`, `ES384`, `ES512`, `PS384`, `PS512`, `RS384`, `RS512` | `token_endpoint_auth_signing_alg_values_supported` |
| `idTokenSigningAlgs` | `readonly string[]` | `['RS256']` | `id_token_signing_alg_values_supported` |
| `claims` | `readonly string[]` | omitted | `claims_supported` |
| `subjectTypes` | `readonly string[]` | `['public']` | `subject_types_supported` |
| `claimsParameterSupported` | `boolean` | `false` | `claims_parameter_supported` |

The default for `idTokenSigningAlgs` is `RS256` because OIDC Discovery section 3 says it MUST be listed.

## authorizationServer

```ts title="signature"
const authorizationServer: (options: AuthorizationServerOptions) => Record<string, unknown>;
```

Returns the document. Members whose value is `undefined` are removed. These members are fixed:

| Member | Value |
| --- | --- |
| `response_types_supported` | `['code']` |
| `response_modes_supported` | `['query']` |
| `code_challenge_methods_supported` | `['S256']` |
| `authorization_response_iss_parameter_supported` | `true` |
| `request_parameter_supported` | `false` |
| `request_uri_parameter_supported` | `false` |

`token_endpoint_auth_signing_alg_values_supported` appears only when `tokenEndpointAuthMethods` includes `private_key_jwt`.

Throws `TypeError` when:

- `issuer` is not an absolute URL (`Issuer must be an absolute URL`).
- `issuer` is not `https`. `http` is allowed only for `localhost`, `127.0.0.1` and `[::1]`.
- `issuer` has a query or fragment ([RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414#section-2)).
- `tokenEndpointAuthSigningAlgs` contains a symmetric or `none` algorithm.

```ts
const document = Metadata.authorizationServer({
  issuer: 'https://op.example.com',
  endpoints: {
    authorization: 'https://op.example.com/authorize',
    token: 'https://op.example.com/token',
    jwks: 'https://op.example.com/jwks',
    userinfo: 'https://op.example.com/userinfo',
  },
  scopes: ['openid', 'profile', 'email'],
  idTokenSigningAlgs: ['ES256', 'RS256'],
});
return Response.json(document);
```

## wellKnownUrls

```ts title="signature"
const wellKnownUrls: (issuer: string) => {
  openidConfiguration: string;
  oauthAuthorizationServer: string;
};
```

Returns the two discovery URLs for `issuer`. A trailing slash on `issuer` is removed first.

- `openidConfiguration` appends `/.well-known/openid-configuration` to the issuer ([OIDC Discovery section 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)).
- `oauthAuthorizationServer` inserts `/.well-known/oauth-authorization-server` between the host and the issuer path ([RFC 8414 section 3.1](https://www.rfc-editor.org/rfc/rfc8414#section-3.1)).

Throws `TypeError` for the same issuer problems as `authorizationServer`.

```ts
const urls = Metadata.wellKnownUrls('https://op.example.com/tenant1');
// urls.openidConfiguration: https://op.example.com/tenant1/.well-known/openid-configuration
// urls.oauthAuthorizationServer: https://op.example.com/.well-known/oauth-authorization-server/tenant1
```

## Spec

- [RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414#section-2): authorization server metadata and issuer rules.
- [RFC 8414 section 3.1](https://www.rfc-editor.org/rfc/rfc8414#section-3.1): well-known URL construction.
- [OIDC Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata): provider metadata.
- [OIDC Discovery section 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig): configuration URL.
- [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207): `authorization_response_iss_parameter_supported`.
