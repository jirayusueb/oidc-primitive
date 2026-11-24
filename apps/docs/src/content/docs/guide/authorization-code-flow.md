---
title: Authorization code flow
description: The OAuth 2.1 authorization code flow with PKCE, step by step, with the module that guards each step.
---

OAuth 2.1 keeps one interactive flow: the authorization code flow with PKCE. The steps below name the module call at each point. The [sequence diagram](/guide/library-and-host/#one-flow-two-owners) shows the same flow end to end.

## 1. Authorization request

The client sends the browser to `/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, and usually `state` and `nonce`.

- Reject before any redirect when `client_id` is unknown or `redirect_uri` fails `RedirectUri.matches`. Render an error page; never redirect to an unverified URI ([RFC 9700 s4.11.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2)).
- `Pkce.validateMethod` rejects anything but `S256`.
- `Scope.parse` and `Resource.audience` resolve what the code will be worth.

## 2. Issue the code

Generate with `Token.generate()` and store only `await Token.hash(code)` with a TTL of 60 seconds or less. Redirect back with `OAuthResponse.redirect`, which adds `iss` ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)).

## 3. Token request

The client posts `grant_type=authorization_code`, `code`, `code_verifier`, and `redirect_uri` to `/token`.

- Authenticate the client: `ClientSecret.parseBasic` plus `Token.matchesHash`, or `ClientAssertion.verify` for `private_key_jwt`. See [Client authentication](/guide/client-authentication/).
- Consume the code atomically (`DELETE ... RETURNING`, `GETDEL`). Only after the delete succeeded, check the client, the `redirect_uri`, and `Pkce.verify`.
- A replayed, spent code must revoke every token issued from it ([OAuth 2.1 draft s7.5.3](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-17#section-7.5.3)). Keep a short tombstone of consumed hashes.

## 4. Issue tokens

`TokenSigner` signs the access token ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)) and the ID token (OIDC Core), with `at_hash` binding. If the client may refresh, generate a refresh token and store only its hash. Respond with `OAuthResponse.json` (`Cache-Control: no-store`).

See [Tokens and keys](/guide/tokens-and-keys/) for lifetimes and rotation, and [Getting started](/guide/getting-started/) for the code.

## 5. Call the API

The resource server verifies with `AccessTokenVerifier` and answers `401` with `Bearer.challenge` when the token is missing. See [Resource servers](/guide/resource-servers/).

## Variants

- Refreshing: [Refresh token rotation](/guide/refresh-token-rotation/).
- Machine-to-machine, no user: [Client credentials](/guide/client-credentials/).
- Multiple issuers in one app: [Multi-tenant](/guide/multi-tenant/).
