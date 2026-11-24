---
title: Authorization requests
description: Check PKCE, redirect URIs, scopes and resource indicators in the order the authorization endpoint needs them.
---

At the authorization endpoint the host parses the request and the library checks each value. The order below matters. The first check decides whether an error may be redirected at all.

## 1. Match the redirect URI

Look up the client. Then call `RedirectUri.matches` with the requested URI and the client's registered list. The comparison is exact string match ([RFC 9700 s4.1.3](https://www.rfc-editor.org/rfc/rfc9700#section-4.1.3)). The only exception is the port of `http://127.0.0.1` and `http://[::1]` ([RFC 8252 s7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)).

If the client is unknown or the URI does not match, render an error page. Do not redirect.

```ts
import { RedirectUri } from 'oidc-primitive';

declare const registered: string[];
declare const errorPage: (message: string) => Response;

const requested = 'http://127.0.0.1:51234/callback';
if (!RedirectUri.matches(requested, registered)) errorPage('Unregistered redirect_uri.');
const registeredUri: string | undefined = RedirectUri.match(requested, registered);
```

`RedirectUri.match` returns the registered URI that matched. `RedirectUri.matches` returns a boolean.

At client registration, call `RedirectUri.validate(uri, { applicationType })`. It rejects fragments, non-loopback `http`, and private-use schemes for `web` clients ([RFC 8252 s7.1](https://www.rfc-editor.org/rfc/rfc8252#section-7.1)). It throws `InvalidRequest`.

```ts
import { RedirectUri } from 'oidc-primitive';

RedirectUri.validate('https://app.example/cb');
RedirectUri.validate('com.example.app:/cb', { applicationType: 'native' });
```

See [RedirectUri](/reference/redirect-uri/).

## 2. Check PKCE

When a `code_challenge` is present, call `Pkce.validateMethod` with `code_challenge_method`. Only `S256` passes. An absent method means `plain` and is rejected ([RFC 9700 s2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1)). Then check the shape of the challenge with `Pkce.isChallenge`.

```ts
import { OAuthError, Pkce } from 'oidc-primitive';

declare const params: URLSearchParams;

const challenge = params.get('code_challenge');
if (challenge !== null) {
	Pkce.validateMethod(params.get('code_challenge_method'));
	if (!Pkce.isChallenge(challenge)) throw new OAuthError.InvalidRequest('code_challenge is malformed');
}
```

Whether a client may omit PKCE is host policy. The library default is strict: `Pkce.verify` requires both values unless you pass `{ required: false }`. The [Example OP](/guide/example-op/) exempts only a confidential client that sent a `nonce`. See [Pkce](/reference/pkce/).

## 3. Parse scopes

`Scope.parse` splits a space-delimited string, drops duplicates and throws `InvalidScope` on a malformed token ([RFC 6749 s3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3)). Whether to drop unknown scopes or reject them is your policy.

```ts
import { Scope } from 'oidc-primitive';

declare const raw: string | null;

const supported = ['openid', 'profile', 'email'] as const;
const requested = Scope.parse(raw);
const granted = Scope.filter(requested, supported);
const wire: string = Scope.format(granted);
```

`Scope.filter` keeps the scopes that appear in the declared list. `Scope.satisfies(granted, { allOf, anyOf })` checks a requirement at a resource. `Scope.make('read')` declares a typed scope constant. See [Scope](/reference/scope/).

## 4. Resolve the resource

When the request carries `resource` parameters, pass them all to `Resource.audience` with the issuer. It returns the single resource, or the issuer when none was sent. It throws `InvalidTarget` for several values, because one token serves one audience ([RFC 8707 s2](https://www.rfc-editor.org/rfc/rfc8707#section-2)).

```ts
import { Resource } from 'oidc-primitive';

declare const params: URLSearchParams;
declare const issuer: string;

const audience: string = Resource.audience(params.getAll('resource'), issuer);
```

Store the audience with the code and use it as `aud` when you sign the access token. See [Resource](/reference/resource/).

## 5. Answer

Success is `OAuthResponse.redirect(redirectUri, { code, state }, { issuer })`. Failure after the redirect URI is verified is `err.toRedirect(redirectUri, { state, issuer })`. Both add `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). See [Discovery and responses](/guide/discovery-and-responses/).

## Host duties here

- Reject unknown clients and unmatched redirect URIs with a page, not a redirect.
- Decide per client whether PKCE is required.
- Store the code as `Token.hash(code)` with a TTL of 60 seconds or less.
- Send framing and referrer headers on login and consent pages. Do not enable CORS on this endpoint.

The full list is in the [Host checklist](/guide/host-checklist/).
