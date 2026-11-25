# oidc-primitive

Security primitives for building an OAuth 2.1 Authorization Server, an OpenID Provider, and the resource servers that accept their tokens. Built on [`jose`](https://github.com/panva/jose), its only dependency.

This is not a server. Each primitive does one spec-defined step: verify a PKCE verifier, match a redirect URI, sign an ID token with `at_hash`, verify an RFC 9068 access token, build a discovery document, or format an OAuth error. Your app owns routes, request parsing, storage, sessions, and the login and consent UI.

```sh
bun add oidc-primitive
```

ESM only. Tested on Bun and Node 20.19+. The source uses only Web APIs (`Request`, `Response`, Web Crypto) and `jose`, so Deno and Workers are targets too, though CI does not run them yet.

## Usage

Every module is a namespace of functions. A few classes bind configuration you reuse, such as an issuer and a signing key.

```ts
import {
	AccessTokenVerifier,
	Keys,
	OAuthError,
	OAuthResponse,
	Pkce,
	Scope,
	TokenSigner,
} from 'oidc-primitive';

const issuer = 'https://id.example.com';
const { publicKey, privateKey } = await Keys.generate('RS256');
const signer = TokenSigner.make({ issuer, key: privateKey, kid: 'k1', alg: 'RS256' });

// Token endpoint, after your storage consumed the authorization code record exactly once.
try {
	await Pkce.verify(form.get('code_verifier'), record.codeChallenge);
	const accessToken = await signer.signAccessToken({
		sub: record.sub,
		aud: 'https://api.example.com',
		client_id: record.clientId,
		scope: 'read',
	});
	const idToken = await signer.signIdToken(
		{ sub: record.sub, aud: record.clientId, nonce: record.nonce },
		{ accessToken },
	);
	return OAuthResponse.json({
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: 600,
		id_token: idToken,
	});
} catch (error) {
	if (error instanceof OAuthError.OAuthError) return error.toResponse();
	throw error;
}
```

A resource server verifies RFC 9068 access tokens. Declared scopes come back typed in `granted`; scopes it does not know are kept in `scope` and never cause a rejection.

```ts
const api = AccessTokenVerifier.make({
	issuer,
	audience: 'https://api.example.com',
	keys: Keys.remoteResolver(`${issuer}/jwks`),
	scopes: [Scope.make('read'), Scope.make('write')],
});

const { claims, granted } = await api.verifyHeaders(request.headers); // granted: ('read' | 'write')[]
```

The class methods call plain functions you can use directly, for example `AccessToken.verify(token, { issuer, audience, keys })` or `IdToken.sign(claims, { issuer, key, kid, alg })`.

## Errors

Expected failures of `verify`, `parse`, `validate` and `resolve` functions throw a subclass of `OAuthError.OAuthError`; none of them reports failure with `null`, a boolean, or a result value. A function with nothing to do, such as `ClientSecret.parseBasic` on a request without an `Authorization` header, returns `undefined`. Predicates (`RedirectUri.matches`, `OpaqueToken.matchesHash`, `Pkce.isChallenge`, `Pkce.isVerifier`) return booleans, and `RedirectUri.find` returns `undefined` when nothing matches. Catch the base class once at your route boundary and rethrow anything that is not an `OAuthError`.

- Verification against remote keys throws `TemporarilyUnavailable` when the JWKS endpoint fails or returns an invalid key set. Answer 503 for it.
- Bad input to a module throws `TypeError` (for example an `algorithms` value outside the allow-list) or `RangeError` (for example `OpaqueToken.generate(8)`). That is a defect in your code, not a client error.

Failures are thrown rather than returned because a failure here is terminal: your boundary turns it into a response and the request ends. If your app models errors as values, it can wrap any call in its own result helper.

## Modules

| Module                | What it does                                                           | Spec                           |
| --------------------- | ---------------------------------------------------------------------- | ------------------------------ |
| `Pkce`                | S256 challenge, method check, verifier check with downgrade protection | RFC 7636, RFC 9700 s4.8.2      |
| `RedirectUri`         | Registration rules and exact matching; only the loopback port may vary | RFC 9700 s4.1.3, RFC 8252 s7.3 |
| `Scope`               | Parse, format, `satisfies({ allOf, anyOf })`, branded literal scopes   | RFC 6749 s3.3                  |
| `Resource`            | Resource indicator validation and token audience                       | RFC 8707                       |
| `OpaqueToken`         | Random credentials, SHA-256 storage hash, constant-time compare        | RFC 6749 s10.10                |
| `ClientSecret`        | `Authorization: Basic` client credentials                              | RFC 6749 s2.3.1                |
| `ClientAssertion`     | `private_key_jwt` verification; `aud` must be the issuer only          | RFC 7523, RFC 10070            |
| `Keys`                | Key generation, public JWKs, JWK Sets, local and remote key resolvers  | RFC 7517, RFC 7638             |
| `IdToken`             | Sign with `at_hash` and `azp`; verify an `id_token_hint`               | OIDC Core s2, s3.1.3.6         |
| `AccessToken`         | Sign and verify JWT access tokens (`typ: at+jwt`)                      | RFC 9068                       |
| `UserClaims`          | Standard claims per scope and the `claims` request parameter           | OIDC Core s5.4, s5.5           |
| `Introspection`       | Active and inactive introspection responses                            | RFC 7662                       |
| `Bearer`              | Header-only bearer extraction and `WWW-Authenticate` challenges        | RFC 6750                       |
| `ServerMetadata`      | Authorization server and OpenID discovery documents, well-known URLs   | RFC 8414, OIDC Discovery       |
| `ResourceMetadata`    | Protected resource metadata and its well-known URL                     | RFC 9728                       |
| `OAuthResponse`       | `no-store` JSON responses and 303 redirects with `iss`                 | RFC 6749 s5.1, RFC 9207        |
| `OAuthError`          | One class per error code, `toResponse()`, `toRedirect()`               | RFC 6749 s5.2, RFC 6750 s3.1   |
| `Redacted`            | Credential wrapper that prints `<redacted>`                            | none                           |
| `TokenSigner`         | Class: one signing key bound to an issuer                              | binds `IdToken`, `AccessToken` |
| `AccessTokenVerifier` | Class: issuer, audience and keys bound for a resource server           | binds `AccessToken`, `Bearer`  |

## Secure defaults

| Default                                  | What is rejected                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| PKCE S256 only                           | `plain`, malformed verifiers, a verifier without a stored challenge      |
| Exact redirect matching                  | Any difference except the port of `http://127.0.0.1` and `http://[::1]`  |
| Client assertion audience is the issuer  | The token endpoint URL, extra audience values, lifetimes over 10 minutes |
| Access token `typ: at+jwt`               | Tokens without it                                                        |
| Algorithms ES256, EdDSA, PS256, RS256    | `none`, HMAC and everything else                                         |
| 30 second clock tolerance                | `exp` and `nbf` outside it                                               |
| Sender-constrained tokens need `confirm` | A token with `cnf` presented as a plain bearer token                     |

Errors never echo the token, secret or assertion they rejected. Generated credentials are `Redacted`, and `OAuthResponse.json` writes their raw value only into the response body.

## What your app still owns

Single-use authorization codes, refresh token rotation, `jti` replay records, sessions, consent, and rate limits. [`docs/host-checklist.md`](../../docs/host-checklist.md) lists each duty, and [`examples/bun-op`](../../examples/bun-op) shows them in a single-file OpenID Provider.

## License

MIT
