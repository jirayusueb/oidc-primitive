---
title: Discovery and responses
description: Publish discovery metadata, select claims, answer introspection, and build responses and errors.
---

These modules build the documents and responses around the token flow. None of them stores anything.

## Metadata

`ServerMetadata.make` builds the document served at `/.well-known/openid-configuration` and the [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) equivalent. It returns a snake_case object. `ServerMetadata.wellKnownUrls(issuer)` gives both URLs, with the well-known segment inserted the way each spec requires.

```ts
import { ServerMetadata, OAuthResponse } from 'oidc-primitive';

const issuer = 'https://op.example';
const metadata = ServerMetadata.make({
	issuer,
	endpoints: {
		authorization: `${issuer}/authorize`,
		token: `${issuer}/token`,
		jwksUri: `${issuer}/jwks`,
		userinfo: `${issuer}/userinfo`,
	},
	scopes: ['openid', 'profile', 'email'],
	idTokenSigningAlgs: ['RS256'],
});
const urls = ServerMetadata.wellKnownUrls(issuer);
const respond = (): Response => OAuthResponse.json(metadata);
```

The issuer must be `https`, or `http` on localhost, with no query or fragment. Otherwise a `TypeError` is thrown.

Defaults you should know about:

- `response_types_supported` is `['code']`. `code_challenge_methods_supported` is `['S256']`. `authorization_response_iss_parameter_supported` is `true`.
- `token_endpoint_auth_methods_supported` defaults to `client_secret_basic`, `client_secret_post` and `private_key_jwt`. Pass `tokenEndpointAuthMethods` to match what your token endpoint accepts.
- `id_token_signing_alg_values_supported` defaults to `['RS256']`.
- `claims_parameter_supported` is `false` unless you set `claimsParameterSupported`. `request_parameter_supported` and `request_uri_parameter_supported` are `false`.

Serve the document yourself. ServerMetadata only builds it. See [ServerMetadata](/reference/server-metadata/).

## Claims

At userinfo and when you build an ID token, return only claims the scopes or the `claims` request parameter allow ([OIDC Core s5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims), [s5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)).

`UserClaims.parseRequest` parses the `claims` parameter and throws `InvalidRequest` when it is malformed. `UserClaims.select` filters your user record. `sub` is always kept.

```ts
import { UserClaims } from 'oidc-primitive';

declare const params: URLSearchParams;
declare const user: Record<string, unknown>;

const request = UserClaims.parseRequest(params.get('claims'));
const forUserinfo = UserClaims.select(user, { scopes: ['openid', 'email'], request, target: 'userinfo' });
const names: string[] = UserClaims.forScopes(['profile']);
```

`target` is `'userinfo'` or `'id_token'`. See [UserClaims](/reference/user-claims/).

## Introspection

[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) responses. Authenticate the caller first ([Client authentication](/guide/client-authentication/)). Then answer `Introspection.active(claims)` for a token the caller may see, and `Introspection.inactive()` for everything else. An unknown, expired or foreign token reveals nothing else.

```ts
import { Introspection, OAuthResponse } from 'oidc-primitive';

declare const live: { scope: string; client_id: string; exp: number; sub: string } | undefined;

const body = live ? Introspection.active({ ...live, token_type: 'Bearer' }) : Introspection.inactive();
const response: Response = OAuthResponse.json(body);
```

`active` sets `active: true` and cannot be overridden by the claims you pass. See [Introspection](/reference/introspection/).

## OAuthResponse

- `OAuthResponse.json(body, { status, headers })` writes a JSON response with `Cache-Control: no-store` and `Pragma: no-cache`. `Redacted` values in the body are unwrapped.
- `OAuthResponse.redirect(redirectUri, params, { issuer })` writes a 303 redirect with the params and `iss` in the query ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). It also sets `Referrer-Policy: no-referrer`.

Use `json` for token, userinfo, introspection and discovery responses. See [OAuthResponse](/reference/oauth-response/).

## OAuthError

Every check throws an `OAuthError.OAuthError` subclass. Catch it once at the edge of your app.

```ts
import { OAuthError } from 'oidc-primitive';

declare const run: () => Promise<Response>;

export const guarded = async (): Promise<Response> => {
	try {
		return await run();
	} catch (err) {
		if (err instanceof OAuthError.OAuthError) return err.toResponse();
		throw err;
	}
};
```

`toResponse()` uses the error's `status` and a no-store JSON body. `toRedirect(redirectUri, { state, issuer })` redirects the error to the client. `OAuthError.fromCode(code, { status, description })` builds an error with any code, for extension specs.

Descriptions are sent to the client. Do not put request input, tokens or secrets in one. See [OAuthError](/reference/oauth-error/).

## Redacted

`Redacted.make(value)` wraps a credential and `Redacted.value(redacted)` reads it back. A wrapped value prints as `<redacted>` in `String()`, `JSON.stringify` and console output. See [Redacted](/reference/redacted/).

## Host duties here

- Serve the discovery document and the JWK Set at the URLs you advertise.
- Authenticate introspection callers and show a token only to the client it was issued to.
- Answer revocation with 200 for unknown tokens ([RFC 7009 s2.2](https://www.rfc-editor.org/rfc/rfc7009#section-2.2)). The library has no revocation helper.
- Catch non-`OAuthError` exceptions and answer `OAuthError.ServerError` without leaking details.

See the [Host checklist](/guide/host-checklist/).
