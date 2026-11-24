# Host checklist

`oidc-primitive` gives you the security-sensitive checks and encodings. Your app owns routes, request parsing, storage, sessions and UI. These duties stay with you.

## Authorization endpoint

- Reject the request before any redirect when `client_id` is unknown or `redirect_uri` fails `RedirectUri.matches`. Render an error page; never redirect to an unverified URI (RFC 9700 s4.11.2).
- Accept only `response_type=code`; call `Pkce.validateMethod` when a `code_challenge` is present.
- Decide per client whether PKCE is required. RFC 9700 s2.1.1 allows confidential OpenID Connect clients that send a `nonce` to omit it; everyone else must send S256.
- Resolve `resource` with `Resource.audience` and store the result with the code.
- Answer with `OAuthResponse.redirect` (adds `iss`, RFC 9207) or `err.toRedirect`.
- Send `Content-Security-Policy: frame-ancestors 'none'` (or `X-Frame-Options: DENY`) and `Referrer-Policy: no-referrer` on login and consent pages (RFC 9700 s4.16, s4.2).
- Do not allow CORS on the authorization endpoint (RFC 9700 s2.6).

## Authorization codes

- Generate with `Token.generate()`, store under `await Token.hash(code)` with a TTL of 60 seconds or less.
- Consume atomically at the token endpoint, then check: `DELETE ... RETURNING` in SQL, `GETDEL` in Redis. Check client, `redirect_uri` and `Pkce.verify` only after the delete succeeded.
- Keep a short-lived tombstone of consumed code hashes. A second use must revoke every token issued from that code (OAuth 2.1 draft-17 s7.5.3).

## Refresh tokens

- Store `Token.hash` only. Rotate on every use with a compare-and-swap; on reuse of a rotated token, revoke the whole grant (OAuth 2.1 draft-17 s4.3.1).
- A short grace window for concurrent retries is your policy; log every grace use.

## Client authentication

- Store client secrets as `Token.hash`; check with `Token.matchesHash`. Parse `Authorization: Basic` with `ClientSecret.parseBasic`.
- For `private_key_jwt`, record the `jti` returned by `ClientAssertion.verify` until `expiresAt` and reject a repeat.
- Rate-limit failed client authentication per `client_id` and IP at the edge.

## Tokens and keys

- Keep access tokens short (`expiresIn` default 10 minutes); JWT access tokens stay valid at resource servers until `exp` even after you revoke the grant.
- Persist signing keys yourself (`Keys.generate(alg, { extractable: true })` plus `jose` `exportJWK`/`importJWK`, or a KMS-backed `CryptoKey`).
- Rotate by publishing the next key in `Keys.jwks` for at least the JWKS cache time before signing with it; keep the retired public key until its last token expires.

## Responses

- Use `OAuthResponse.json` for token, userinfo and introspection responses (`Cache-Control: no-store`).
- Revocation (RFC 7009) answers 200 for unknown tokens too; delete the grant behind a valid refresh token.
- Introspection callers must be authenticated; return `Introspection.inactive()` unless the caller may see that token.
