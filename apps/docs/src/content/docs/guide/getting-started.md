---
title: Getting started
description: Install oidc-primitive and wire its checks into an authorization endpoint and a token endpoint.
---

`oidc-primitive` is a set of server-side checks and encodings for OAuth 2.1 and OpenID Connect. You write the routes. The library answers the security questions inside them.

## Install

The package is pre-1.0 and not yet on npm. Once published, install it with one of:

```sh
bun add oidc-primitive
npm i oidc-primitive
```

Every module is a namespace on the package root:

```ts
import { OAuthError, OAuthResponse, Pkce, RedirectUri, Token } from 'oidc-primitive';
```

## At the authorization endpoint

Check the redirect URI first. If it does not match a registered URI, render an error page. Never redirect to it ([RFC 9700 s4.11.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2)).

Then check PKCE, generate a code and store only its hash. [Token](/reference/token/) generates and hashes. [Pkce](/reference/pkce/) checks the challenge. [RedirectUri](/reference/redirect-uri/) does the exact match.

```ts
import { OAuthError, OAuthResponse, Pkce, RedirectUri, Token } from 'oidc-primitive';

declare const issuer: string;
declare const registeredRedirectUris: string[];
declare const storeCode: (hash: string, challenge: string, redirectUri: string) => Promise<void>;
declare const errorPage: (message: string) => Response;

export const authorize = async (params: URLSearchParams): Promise<Response> => {
	const redirectUri = params.get('redirect_uri');
	if (!redirectUri || !RedirectUri.matches(redirectUri, registeredRedirectUris)) {
		return errorPage('Unregistered redirect_uri.');
	}
	const state = params.get('state') ?? undefined;
	try {
		Pkce.checkMethod(params.get('code_challenge_method'));
		const challenge = params.get('code_challenge');
		if (!Pkce.isChallenge(challenge)) throw new OAuthError.InvalidRequest('code_challenge is malformed');

		const code = Token.generate();
		await storeCode(await Token.hash(code), challenge, redirectUri);
		return OAuthResponse.redirect(redirectUri, { code, state }, { issuer });
	} catch (err) {
		if (err instanceof OAuthError.OAuthError) return err.toRedirect(redirectUri, { state, issuer });
		throw err;
	}
};
```

`OAuthResponse.redirect` adds `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). `toRedirect` does the same for errors ([RFC 6749 s4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1)).

## At the token endpoint

Hash the presented code, consume the stored record, and verify the PKCE verifier against the stored challenge. Any failure throws an `OAuthError`. Turn it into a response with `toResponse`.

```ts
import { OAuthError, OAuthResponse, Pkce, Token } from 'oidc-primitive';

declare const consumeCode: (
	hash: string,
) => Promise<{ challenge: string; redirectUri: string } | undefined>;
declare const issueAccessToken: () => Promise<string>;

export const token = async (form: URLSearchParams): Promise<Response> => {
	try {
		const code = form.get('code');
		if (!code) throw new OAuthError.InvalidRequest('code is required');
		const record = await consumeCode(await Token.hash(code));
		if (!record) throw new OAuthError.InvalidGrant('code is invalid');
		if (form.get('redirect_uri') !== record.redirectUri) {
			throw new OAuthError.InvalidGrant('redirect_uri does not match');
		}
		await Pkce.verify(form.get('code_verifier'), record.challenge);
		return OAuthResponse.json({
			access_token: await issueAccessToken(),
			token_type: 'Bearer',
			expires_in: 600,
		});
	} catch (err) {
		if (err instanceof OAuthError.OAuthError) return err.toResponse();
		throw err;
	}
};
```

`consumeCode` must delete the record in one atomic step. See [Host checklist](/guide/host-checklist/).

## Where to go next

- [Library and host](/guide/library-and-host/): what the package does and what you own.
- [Example OP](/guide/example-op/): a complete provider in one file.
- [Authorization requests](/guide/authorization-requests/), [Client authentication](/guide/client-authentication/), [Tokens and keys](/guide/tokens-and-keys/): one endpoint at a time.
- [Host checklist](/guide/host-checklist/): the duties the library cannot do for you.
