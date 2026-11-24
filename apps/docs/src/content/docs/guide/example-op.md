---
title: Example OP
description: A walkthrough of examples/bun-op, a single-file OpenID Provider built only from oidc-primitive.
---

`examples/bun-op` is a complete authorization code flow provider in one file, `index.ts`. It uses `oidc-primitive`, Bun and `bun:sqlite`. It is for development only: synthetic users, automatic consent, and signing keys regenerated at every start.

Read it next to the [Host checklist](/guide/host-checklist/). The library does the security checks. The file is the host: routes, storage, sessions and UI.

## Run it

From `examples/bun-op`:

```sh
bun install
bun run start     # http://localhost:3000
bun run smoke     # discovery, authorize with PKCE S256, login, token, userinfo, refresh, introspect, revoke
```

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ISSUER` | `http://localhost:3000` | Issuer identifier. A path in it is honoured. |
| `PORT` | `3000` | Listen port. |
| `DATABASE` | `:memory:` | SQLite path. |
| `CLIENTS` | public client `demo` | JSON array of `{ client_id, client_secret?, redirect_uris, token_endpoint_auth_method, pkce?, grant_types? }`. |

The default client `demo` is a public client with redirect URI `http://127.0.0.1:3001/callback`. `token_endpoint_auth_method` is `client_secret_basic`, `client_secret_post` or `none`. `pkce` is `required` or `oidc-nonce`.

## Endpoints

Paths are under the issuer path.

| Endpoint | Path |
| --- | --- |
| Discovery | `/.well-known/openid-configuration`, plus the [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) path-inserted URL |
| JWK Set | `/jwks` |
| Authorization | `/authorize` |
| Login page | `/login` |
| Token | `/token` |
| UserInfo | `/userinfo` |
| Introspection | `/introspect` |
| Revocation | `/revoke` |
| Health | `/healthz` |

## What it does not support

- `private_key_jwt`. The example may not import jose, and a JWKS resolver comes from jose. See [Client authentication](/guide/client-authentication/) for the real-host version.
- RP-initiated logout.
- `request` and `request_uri` parameters.
- Response types other than `code`, and response modes other than `query`.
- Access tokens with a `resource` audience at `/userinfo`. UserInfo accepts tokens whose `aud` is the issuer.

Revoking an access or refresh token revokes its whole grant. Expired rows are never swept from SQLite.

## Which module each endpoint uses

| Endpoint | Modules |
| --- | --- |
| Startup | [Keys](/reference/keys/), [TokenSigner](/reference/token-signer/), [AccessTokenVerifier](/reference/access-token-verifier/), [Metadata](/reference/metadata/), [RedirectUri](/reference/redirect-uri/), [Token](/reference/token/) |
| `/.well-known/openid-configuration`, `/jwks` | [Metadata](/reference/metadata/), [Keys](/reference/keys/), [OAuthResponse](/reference/oauth-response/) |
| `/authorize` | [RedirectUri](/reference/redirect-uri/), [Scope](/reference/scope/), [Pkce](/reference/pkce/), [Resource](/reference/resource/), [Claims](/reference/claims/), [IdToken](/reference/id-token/), [Token](/reference/token/), [OAuthResponse](/reference/oauth-response/), [OAuthError](/reference/oauth-error/) |
| `/login` | [Token](/reference/token/), [Redacted](/reference/redacted/) |
| `/token` | [ClientSecret](/reference/client-secret/), [Token](/reference/token/), [Pkce](/reference/pkce/), [Scope](/reference/scope/), [Resource](/reference/resource/), [TokenSigner](/reference/token-signer/), [Claims](/reference/claims/), [OAuthResponse](/reference/oauth-response/) |
| `/userinfo` | [Bearer](/reference/bearer/), [AccessTokenVerifier](/reference/access-token-verifier/), [Claims](/reference/claims/), [OAuthResponse](/reference/oauth-response/) |
| `/introspect` | [ClientSecret](/reference/client-secret/), [AccessTokenVerifier](/reference/access-token-verifier/), [Introspection](/reference/introspection/) |
| `/revoke` | [ClientSecret](/reference/client-secret/), [Token](/reference/token/) |

## Walkthrough

### Startup: keys, signer, verifier, metadata

The example generates an RS256 key, binds it into a signer, publishes the JWK Set, and builds a verifier. A public `CryptoKey` is a valid key for verification, so no jose resolver is needed.

```ts
import { AccessTokenVerifier, Keys, TokenSigner } from 'oidc-primitive';

declare const issuer: string;

const { publicKey, privateKey } = await Keys.generate('RS256');
const kid = 'op-1';
const signer = TokenSigner.make({ issuer, key: privateKey, kid, alg: 'RS256' });
const jwks = await Keys.jwks([{ key: publicKey, kid, alg: 'RS256' }]);
const verifier = AccessTokenVerifier.make({ issuer, audience: issuer, keys: publicKey });
```

Client secrets are hashed when the clients are loaded, and redirect URIs are validated:

```ts
import { RedirectUri, Token } from 'oidc-primitive';

declare const c: { client_secret?: string; redirect_uris: string[] };

for (const uri of c.redirect_uris) RedirectUri.validate(uri);
const secretHash = c.client_secret ? await Token.hash(c.client_secret) : undefined;
```

### /authorize

An unknown client or unregistered redirect URI gets an error page. Every later error is redirected with `toRedirect`.

```ts
import { OAuthError, RedirectUri } from 'oidc-primitive';

declare const p: URLSearchParams;
declare const issuer: string;
declare const redirectUri: string;
declare const registered: string[];
declare const errorPage: (message: string) => Response;
declare const authorizeChecked: () => Promise<Response>;

if (!RedirectUri.matches(redirectUri, registered)) {
	errorPage('Unknown client or unregistered redirect_uri.');
}
const state = p.get('state') ?? undefined;
try {
	await authorizeChecked();
} catch (err) {
	if (err instanceof OAuthError.OAuthError) err.toRedirect(redirectUri, { state, issuer });
}
```

`authorizeChecked` rejects `request`, `request_uri` and `registration` with `RequestNotSupported`, `RequestUriNotSupported` and `RegistrationNotSupported`, and anything but `response_type=code` with `UnsupportedResponseType`. Then it checks scope, PKCE, resource and claims:

```ts
import { Claims, OAuthError, Pkce, Resource, Scope } from 'oidc-primitive';

declare const p: URLSearchParams;
declare const issuer: string;
declare const scopesSupported: string[];
declare const exempt: boolean;

const scope = Scope.parse(p.get('scope')).filter((s) => scopesSupported.includes(s));
const challenge = p.get('code_challenge') ?? undefined;
if (challenge !== undefined) {
	Pkce.checkMethod(p.get('code_challenge_method'));
	if (!Pkce.isChallenge(challenge)) throw new OAuthError.InvalidRequest('code_challenge is malformed');
} else if (!exempt) {
	throw new OAuthError.InvalidRequest('PKCE with code_challenge_method=S256 is required');
}
const audience = Resource.audience(p.getAll('resource'), issuer);
const claims = Claims.parseRequest(p.get('claims'));
```

`exempt` is the example's PKCE policy: only a confidential client registered as `oidc-nonce` that sent a `nonce` may skip PKCE. This is host policy, not a library rule.

After login, the example generates the code, stores its hash for 60 seconds and redirects with `iss`:

```ts
import { OAuthResponse, Token } from 'oidc-primitive';

declare const db: { query: (sql: string) => { run: (...args: unknown[]) => unknown } };
declare const issuer: string;
declare const redirectUri: string;
declare const state: string | undefined;
declare const grantJson: string;

const code = Token.generate();
db.query('INSERT INTO codes(hash, data, exp) VALUES (?, ?, ?)').run(
	await Token.hash(code),
	grantJson,
	Math.floor(Date.now() / 1000) + 60,
);
OAuthResponse.redirect(redirectUri, { code, state }, { issuer });
```

### /token

Client authentication accepts Basic, a form secret, or none. It requires the method registered for the client:

```ts
import { ClientSecret, OAuthError, Redacted, Token } from 'oidc-primitive';

declare const req: Request;
declare const f: URLSearchParams;
declare const clients: Map<string, { method: string; secretHash?: string }>;

const basic = ClientSecret.parseBasic(req.headers.get('authorization'));
const secret = basic ? Redacted.value(basic.clientSecret) : f.get('client_secret');
const method = basic ? 'client_secret_basic' : secret !== null ? 'client_secret_post' : 'none';
const client = clients.get(basic?.clientId ?? f.get('client_id') ?? '');
if (!client || client.method !== method) throw new OAuthError.InvalidClient('client authentication failed');
if (method !== 'none' && !(await Token.matchesHash(secret!, client.secretHash!))) {
	throw new OAuthError.InvalidClient('client authentication failed');
}
```

For `authorization_code`, the code is consumed with one `DELETE ... RETURNING`. A replayed code revokes the grant behind it. Then `redirect_uri` is compared and `Pkce.verify` runs:

```ts
import { OAuthError, Pkce, Token } from 'oidc-primitive';

declare const f: URLSearchParams;
declare const db: { query: (sql: string) => { get: (...args: unknown[]) => unknown } };
declare const g: { redirect_uri: string; challenge?: string; pkce_required: boolean };

const h = await Token.hash(f.get('code')!);
const row = db.query('DELETE FROM codes WHERE hash = ? RETURNING data, exp').get(h);
if (f.get('redirect_uri') !== g.redirect_uri) throw new OAuthError.InvalidGrant('redirect_uri does not match');
await Pkce.verify(f.get('code_verifier'), g.challenge, { required: g.pkce_required });
```

Tokens are signed with the signer. The `at_hash` is bound with `accessToken`, and `nonce` is echoed only on the first response:

```ts
import { Claims, OAuthResponse, Scope, type TokenSigner } from 'oidc-primitive';

declare const signer: TokenSigner.TokenSigner;
declare const g: { sub: string; audience: string; client_id: string; grant_id: string; nonce?: string; claims: Claims.Request };
declare const scope: string[];
declare const user: Record<string, unknown>;

const access = await signer.accessToken({
	sub: g.sub,
	aud: g.audience,
	client_id: g.client_id,
	scope: Scope.format(scope),
	gid: g.grant_id,
});
const idToken = await signer.idToken(
	{
		...Claims.select(user, { scopes: [], request: g.claims, target: 'id_token' }),
		sub: g.sub,
		aud: g.client_id,
		nonce: g.nonce,
	},
	{ accessToken: access },
);
OAuthResponse.json({ access_token: access, token_type: 'Bearer', expires_in: 600, id_token: idToken });
```

Refresh tokens rotate with `UPDATE refresh SET used = 1 WHERE hash = ? AND used = 0`. If no row changes, the token was already used, and the grant is revoked.

### /userinfo

```ts
import { AccessTokenVerifier, Bearer, Claims, OAuthError, OAuthResponse } from 'oidc-primitive';

declare const req: Request;
declare const verifier: AccessTokenVerifier.AccessTokenVerifier;
declare const user: Record<string, unknown>;
declare const requestedClaims: Claims.Request;

const bearer = Bearer.extract(req.headers);
if (bearer === undefined) throw new OAuthError.InvalidToken();
const v = await verifier.verify(bearer);
if (!v.scope.includes('openid')) throw new OAuthError.InsufficientScope('openid');
OAuthResponse.json(Claims.select(user, { scopes: v.scope, request: requestedClaims, target: 'userinfo' }));
```

### /introspect and /revoke

Both authenticate the caller with the same client authentication as `/token`. Introspection answers `inactive` unless the token belongs to the caller:

```ts
import { Introspection } from 'oidc-primitive';

declare const owned: boolean;
declare const claims: { scope: string; client_id: string; sub: string };

Introspection.response(owned ? Introspection.active(claims) : Introspection.inactive());
```

Revocation answers 200 whether or not the token existed ([RFC 7009 s2.2](https://www.rfc-editor.org/rfc/rfc7009#section-2.2)).

### Errors at the edge

`Bun.serve` wraps every route. An `OAuthError` becomes its response. Anything else is logged and becomes `ServerError`:

```ts
import { OAuthError } from 'oidc-primitive';

declare const handle: (req: Request) => Promise<Response>;
declare const req: Request;

let res: Response;
try {
	res = await handle(req);
} catch (err) {
	if (err instanceof OAuthError.OAuthError) res = err.toResponse();
	else {
		console.error(err);
		res = new OAuthError.ServerError().toResponse();
	}
}
```

## Host duties the example shows

- Consume codes atomically and keep a tombstone of spent codes.
- Rotate refresh tokens with compare-and-swap.
- Never redirect to an unverified redirect URI.
- Send framing and referrer headers on pages.

The example skips CSRF protection on its login form. Do not copy that. See the [Host checklist](/guide/host-checklist/).
