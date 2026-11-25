# bun-op

A single-file OpenID Provider (`index.ts`) built only from `oidc-primitive`, Bun and `bun:sqlite`. Dev only: synthetic users, automatic consent, keys regenerated at start.

From a fresh clone to a verified `id_token` and `access_token` in four commands:

```sh
git clone https://github.com/jirayusueb/oidc-primitive.git
cd oidc-primitive
bun install                    # also builds oidc-primitive (prepare script)
bun run --filter bun-op smoke  # authorize (PKCE S256) -> login -> token -> verify id_token -> userinfo -> refresh -> introspect -> revoke; prints elapsed ms
```

Run the provider itself with `bun run --filter bun-op start` (http://localhost:3000, issuer from `ISSUER`).

Env: `ISSUER` (default `http://localhost:3000`), `PORT`, `DATABASE` (sqlite path, default `:memory:`), `CLIENTS` (JSON array of
`{ client_id, client_secret?, jwks_uri?, redirect_uris, token_endpoint_auth_method: client_secret_basic|client_secret_post|private_key_jwt|none, pkce?: 'required'|'oidc-nonce', grant_types? }`; `private_key_jwt` clients need `jwks_uri` and their assertion `jti` values are stored until expiry; default: public client `demo`, redirect `http://127.0.0.1:3001/callback`).

Endpoints (under the issuer path): `/.well-known/openid-configuration` (also the RFC 8414 path-inserted URL), `/jwks`, `/authorize`, `/login`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/healthz`.

Not supported: RP-initiated logout, `request`/`request_uri`, non-`code` response types, access tokens with a `resource` audience at `/userinfo` (userinfo accepts `aud` = issuer only).
Revoking an access or refresh token revokes its whole grant.
