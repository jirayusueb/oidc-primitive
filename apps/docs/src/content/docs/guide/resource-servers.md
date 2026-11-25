---
title: Resource servers
description: Verify the provider's JWT access tokens at an API and publish protected resource metadata.
---

An API that accepts the provider's access tokens needs no storage and no client secrets. It needs the issuer, its own audience and the provider's public keys.

## Verify the token

`AccessTokenVerifier.make` binds an issuer, an audience and a key source. `keys` is a public `CryptoKey`, a JWK, or a resolver. `Keys.remoteResolver` builds a caching resolver over the provider's `jwks_uri`. jose refetches once on an unknown `kid`.

`verifier.verifyHeaders(headers)` reads the bearer token and verifies it per [RFC 9068 s4](https://www.rfc-editor.org/rfc/rfc9068#section-4).

```ts
import { AccessTokenVerifier, Keys, OAuthError } from 'oidc-primitive';

const issuer = 'https://op.example';
const verifier = AccessTokenVerifier.make({
	issuer,
	audience: 'https://api.example',
	keys: Keys.remoteResolver(`${issuer}/jwks`),
	scopes: ['orders:read', 'orders:write'],
});

export const handle = async (request: Request): Promise<Response> => {
	try {
		const { claims, granted } = await verifier.verifyHeaders(request.headers);
		if (!granted.includes('orders:read')) throw new OAuthError.InsufficientScope('orders:read');
		return Response.json({ sub: claims.sub });
	} catch (err) {
		if (err instanceof OAuthError.OAuthError) return err.toResponse();
		throw err;
	}
};
```

The result has `claims` (the verified payload), `scope` (every scope in the token) and `granted` (the declared scopes the token holds). Scopes outside `scopes` are ignored, not rejected.

What it rejects:

- No `Authorization` header with a Bearer credential: `MissingToken`, a 401 with a bare `Bearer` challenge ([RFC 6750 s3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)).
- A bad signature, issuer, audience, `typ`, expiry or missing claim: `InvalidToken`, a 401 with a Bearer challenge. The token is never echoed.
- A key fetch failure: `TemporarilyUnavailable`, a 503.
- A token with a `cnf` claim: rejected unless you pass `confirm`. `confirm` receives `cnf` and throws to reject.

Only `ES256`, `EdDSA`, `PS256` and `RS256` are accepted. `clockTolerance` defaults to 30 seconds. See [AccessTokenVerifier](/reference/access-token-verifier/) and [AccessToken](/reference/access-token/).

To check a token without a request, call `verifier.verify(token)`.

For route-level scope rules, use `Scope.satisfies`:

```ts
import { Scope } from 'oidc-primitive';

declare const scope: string[];

const allowed: boolean = Scope.satisfies(scope, { allOf: ['orders:read'], anyOf: ['admin', 'support'] });
```

## Read the Bearer header

`AccessTokenVerifier` already calls `Bearer.parse`. Use it directly when you verify elsewhere. It reads only the `Authorization` header, never the query or body ([RFC 6750 s2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)). It returns `undefined` when no Bearer credential is present and throws `InvalidToken` when one is malformed.

`Bearer.challenge` builds a `WWW-Authenticate: Bearer` value:

```ts
import { Bearer } from 'oidc-primitive';

declare const headers: Headers;

const token: string | undefined = Bearer.parse(headers);
const challenge: string = Bearer.challenge({
	realm: 'api',
	error: 'invalid_token',
	scope: 'orders:read',
});
```

It throws `TypeError` for characters outside [RFC 6750 s3](https://www.rfc-editor.org/rfc/rfc6750#section-3). See [Bearer](/reference/bearer/).

## Publish resource metadata

`ResourceMetadata.make` builds the [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) document. `resource` must be an `https` URL without a fragment, and `authorizationServers` must not be empty. `ResourceMetadata.wellKnownUrl(resource)` gives the URL to serve it at.

```ts
import { Bearer, ResourceMetadata } from 'oidc-primitive';

const resource = 'https://api.example';
const metadata = ResourceMetadata.make({
	resource,
	authorizationServers: ['https://op.example'],
	scopesSupported: ['orders:read', 'orders:write'],
});
const metadataUrl = ResourceMetadata.wellKnownUrl(resource);
```

Point unauthenticated clients to it with the `resource_metadata` challenge parameter ([RFC 9728 s5.1](https://www.rfc-editor.org/rfc/rfc9728#section-5.1)). `MissingToken.toResponse()` sends a bare `Bearer`, so build this response yourself:

```ts
import { Bearer, ResourceMetadata } from 'oidc-primitive';

const unauthorized = (): Response =>
	new Response(null, {
		status: 401,
		headers: {
			'WWW-Authenticate': Bearer.challenge({
				resource_metadata: ResourceMetadata.wellKnownUrl('https://api.example'),
			}),
		},
	});
```

See [ResourceMetadata](/reference/resource-metadata/).

## Host duties here

- Fetch the provider's keys from its `jwks_uri` and expect rotation.
- A JWT access token stays valid until `exp` after the provider revokes the grant. For immediate revocation, call the provider's introspection endpoint.
- Serve the metadata document at the well-known URL.
- Check the scopes each route needs.

See the [Host checklist](/guide/host-checklist/).
