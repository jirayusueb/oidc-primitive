---
title: Library and host
description: What oidc-primitive checks, what your application owns, and the conventions every module shares.
---

The package is a set of functions. It holds no state, opens no sockets and reads no storage. Your application is the host.

## What the library does

- Validates and compares security-sensitive values: PKCE, redirect URIs, scopes, resource indicators, client credentials, client assertions, tokens.
- Signs and verifies JWTs through [jose](https://github.com/panva/jose): ID tokens, [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) access tokens, client assertions.
- Builds documents and responses with the right headers: discovery metadata, JWK Sets, introspection bodies, `no-store` JSON, error responses.

## What the host owns

| Concern | Host duty |
| --- | --- |
| Routes and HTTP | Routing, method checks, parsing query strings, forms and headers. |
| Storage | Clients, authorization codes, refresh tokens, grants, replay records. |
| Atomicity | Consuming a code once, rotating a refresh token with compare-and-swap. |
| Sessions and UI | Login, consent, error pages, CSRF, framing headers. |
| Keys | Persisting signing keys, rotating them, publishing the JWK Set. |
| Policy | Which clients may skip PKCE, scope grants, token lifetimes, rate limits. |

The [Host checklist](/guide/host-checklist/) lists these duties per endpoint.

## Runtime

The library uses Web APIs (`Request`, `Response`, `Headers`, `URL`, `crypto.subtle`) and `jose`. It does not import Node or Bun modules. It runs where those exist: Bun, Node and edge runtimes. Every handler takes and returns Web `Request` and `Response` objects or plain values, so you can mount it in any framework.

## Modules are namespaces

The package root exports each module as a namespace.

```ts
import { Pkce, Token } from 'oidc-primitive';

const verifier = 'a'.repeat(43);
const challenge = await Pkce.challenge(verifier);
const code = Token.generate();
```

Parameters that name a value you looked up (a stored challenge, a registered URI list) are plain arguments. The library never fetches them.

## Secrets are `Redacted`

[Token](/reference/token/) generates credentials as `Redacted<string>`. A `Redacted` value prints as `<redacted>` in strings, JSON and console output. [OAuthResponse](/reference/oauth-response/) unwraps it when it writes a response body.

```ts
import { Redacted, Token } from 'oidc-primitive';

const code = Token.generate();
String(code); // '<redacted>'
const raw: string = Redacted.value(code);
```

Call `Redacted.value` only where the raw value must leave the process, for example in a `Set-Cookie` header. `Token.hash`, `Token.equals` and `Token.matchesHash` accept either a string or a `Redacted<string>`. `ClientSecret.parseBasic` returns the client secret as `Redacted<string>`. See [Redacted](/reference/redacted/).

## Errors are `OAuthError`

Checks throw instances of `OAuthError.OAuthError` or one of its subclasses: `InvalidRequest`, `InvalidGrant`, `InvalidClient`, `InvalidScope`, `InvalidTarget`, `InvalidToken` and others. Each carries `code`, `status` and an optional `description`. The description is sent to the client, so it never contains request input.

An error turns into a response in one call:

- `err.toResponse()` gives the JSON error response of [RFC 6749 s5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2). `InvalidClient`, `InvalidToken`, `InsufficientScope` and `MissingToken` add a `WWW-Authenticate` header.
- `err.toRedirect(redirectUri, { state, issuer })` gives the authorization error redirect of [RFC 6749 s4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1), with `iss`.

```ts
import { OAuthError } from 'oidc-primitive';

declare const handle: (request: Request) => Promise<Response>;

export const fetch = async (request: Request): Promise<Response> => {
	try {
		return await handle(request);
	} catch (err) {
		if (err instanceof OAuthError.OAuthError) return err.toResponse();
		console.error(err);
		return new OAuthError.ServerError().toResponse();
	}
};
```

Programmer errors are different. A bad argument, such as a scope that is not a valid token or an issuer that is not a valid URL, throws `TypeError` or `RangeError`. Treat those as bugs, not as client errors. See [OAuthError](/reference/oauth-error/).

## Next

[Getting started](/guide/getting-started/) wires these pieces into two endpoints. The [Example OP](/guide/example-op/) wires all of them.
