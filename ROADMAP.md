# Roadmap

`oidc-primitive` ships security checks and encodings for building an OAuth 2.1 Authorization Server, an OpenID Provider, and the resource servers that accept their tokens. The host app owns routes, storage, sessions, and UI. Every milestone below adds modules in that shape and nothing else.

A milestone is done when `examples/bun-op` passes the OpenID Foundation conformance plans named for it, with zero FAILED or INTERRUPTED modules. A module enters a milestone only through a design decision. Status as of 2026-11-24.

## Use cases

### Auth flows

Every OAuth and OpenID Connect flow appears below with its status. The host owns each endpoint and calls the listed modules in the order the spec requires. `examples/bun-op` shows that order for the authorization code, refresh token, client credentials, UserInfo, introspection, and revocation flows.

| Flow | Spec | Status | Modules the host composes |
| --- | --- | --- | --- |
| Authorization code with PKCE, including OIDC sign-in | RFC 6749 s4.1, RFC 7636, OIDC Core s3.1 | v1.0 | `RedirectUri`, `Pkce`, `Scope`, `Resource`, `OpaqueToken`, `OAuthResponse.redirect`, `ClientSecret` or `ClientAssertion`, and `TokenSigner` |
| Refresh token with rotation | OAuth 2.1 draft-17 s4.3 | v1.0 | `OpaqueToken` and `TokenSigner`. Rotation and reuse detection run in host storage, as `docs/host-checklist.md` describes. |
| Client credentials | RFC 6749 s4.4 | v1.0 | `ClientSecret` or `ClientAssertion`, `Scope`, `Resource`, and `AccessToken` |
| UserInfo | OIDC Core s5.3 | v1.0 | `AccessTokenVerifier`, `UserClaims.select`, and `OAuthResponse.json` |
| Token introspection | RFC 7662 | v1.0 | `ClientSecret` or `ClientAssertion`, and `Introspection` |
| Token revocation | RFC 7009 | v1.0, host only | `ClientSecret`, `OpaqueToken.hash`, and `OAuthResponse.json({})` |
| Resource server access | RFC 6750, RFC 9068, RFC 9728 | v1.0 | `Bearer`, `AccessTokenVerifier`, `ResourceMetadata`, and `OAuthError.toResponse` |
| RP-initiated logout | OIDC RP-Initiated Logout 1.0 | v1.0 modules, conformance gate in v1.1 | `IdToken.verify` with `allowExpired`, and `RedirectUri.matches` |
| Third-party-initiated login | OIDC Core s4 | Host only | None. The host redirects to the client's registered `initiate_login_uri`. |
| Pushed authorization requests | RFC 9126 | v1.1 | `Par`, then the authorization code modules |
| DPoP-bound tokens | RFC 9449 | v1.1 | `Dpop` and the `confirm` option of `AccessTokenVerifier` |
| Device authorization | RFC 8628 | v1.1 | `DeviceCode`, `OpaqueToken`, and `AccessToken`. The `authorization_pending`, `slow_down`, and `expired_token` errors come from `OAuthError.fromCode`. |
| MCP clients identified by a metadata URL | CIMD draft 03 | v1.1 | `ClientMetadataDocument`, then the authorization code modules |
| Form post response mode | OAuth 2.0 Form Post Response Mode | v1.1 | `FormPost` |
| Back-channel logout | OIDC Back-Channel Logout 1.0 | v1.1 | `LogoutToken` |
| Dynamic client registration | RFC 7591, OIDC Registration | Open decision for v1.1 | None yet |
| Token exchange | RFC 8693 | v1.2 | `TokenExchange`, `AccessTokenVerifier` for the subject token, and `AccessToken` |
| Step-up authentication | RFC 9470 | v1.2 | `StepUp` and `Bearer.challenge` |
| FAPI 2.0 authorization code | FAPI 2.0 Security Profile | v1.2 | The FAPI 2.0 preset with `Par`, `Dpop`, and `ClientAssertion` |
| mTLS client authentication and bound tokens | RFC 8705 | Later | None yet |
| Signed request objects and JWT responses | RFC 9101, JARM | Later | None yet |
| Client-initiated backchannel authentication | CIBA Core 1.0 | Later | None yet |
| Front-channel logout and session management | OIDC Front-Channel Logout 1.0, OIDC Session Management 1.0 | Later | None yet |
| JWT bearer grant and ID-JAG | RFC 7523 s2.1, ID-JAG draft 06 | Watch list | None yet |
| First-party apps | First-party apps draft 04 | Watch list | None yet |
| Transaction tokens | Transaction Tokens draft 11 | Watch list | None yet |
| SAML 2.0 bearer grant | RFC 7522 | Not in any plan | None |
| Implicit and hybrid response types | RFC 6749 s4.2, OIDC Core s3.2 and s3.3 | Not planned | None. OAuth 2.1 removes the implicit grant. |
| Resource owner password credentials | RFC 6749 s4.3 | Not planned | None. OAuth 2.1 and RFC 9700 s2.4 remove it. |
| `client_secret_jwt` client authentication | OIDC Core s9 | Not planned | None |

### Multi-tenant authorization servers

A tenant is an issuer. Every function that depends on the issuer takes `issuer` as an argument, and the host builds one `TokenSigner` and one `AccessTokenVerifier` per tenant. The package keeps no global state, so tenants share nothing through it. `ServerMetadata.wellKnownUrls` handles subdomain issuers (`https://a.as.example`) and path issuers (`https://as.example/tenant/a`).

The host resolves the tenant from the request host or path before it runs any check. The host also keys its storage by issuer, which covers signing keys, clients, codes, refresh tokens, and replay records.

| Milestone | Work |
| --- | --- |
| v1.0 | Cross-tenant isolation tests and a tenancy section in `docs/host-checklist.md` (see the v1.0 list) |
| v1.1 | `AccessTokenVerifier.forIssuers`, for one resource server that accepts tokens from several tenants |

### API keys

No IETF or OpenID Foundation spec defines API keys. The package supports two ways to use them.

1. Exchange the key for an access token. This is the recommended way, and it works with v1.0. The client sends the API key as its client secret in a `client_credentials` request. The token endpoint checks it with `ClientSecret.parseBasic` and `OpaqueToken.matchesHash`, then returns a short-lived JWT access token whose `iss` is the tenant. Resource servers see only RFC 9068 tokens, so they need no key lookup. When the host revokes a key, the key stops working at once, and tokens issued with it stay valid until they expire.
2. Check the key at the resource server on every request. The `ApiKey` module in v1.1 covers this case. The host stores `OpaqueToken.hash` of each key together with its tenant and scopes, and the resource server looks the key up by that hash.

## v1.0: code flow, OIDC Core, resource servers

The modules are written. Commit `e082417` passed 93 tests on Bun and Node, `tsc`, lint, and the `.d.ts` check.

| Area | Modules | Specs |
| --- | --- | --- |
| Authorization request checks | `Pkce`, `RedirectUri`, `Scope`, `Resource` | RFC 7636 (S256 only), RFC 9700, RFC 8252, RFC 8707 |
| Client authentication | `ClientSecret`, `ClientAssertion`, `OpaqueToken` | RFC 6749 s2.3.1, RFC 7523 with the RFC 10070 issuer-only `aud` rule |
| Tokens | `IdToken`, `AccessToken`, `TokenSigner`, `Keys` | OIDC Core, RFC 9068, RFC 7517, RFC 7638 |
| Resource servers | `AccessTokenVerifier`, `Bearer`, `ResourceMetadata` | RFC 9068, RFC 6750, RFC 9728 |
| Metadata and responses | `ServerMetadata`, `UserClaims`, `Introspection`, `OAuthResponse`, `OAuthError`, `Redacted` | RFC 8414, OIDC Discovery, RFC 7662, RFC 9207 |

These items remain before `1.0.0`:

- [x] Run `bun run conformance` and pass `oidcc-basic-certification-test-plan` and `oidcc-config-certification-test-plan`. Suite v5.3.4 on 2026-11-25: 36 Basic and 2 Config modules, 1940 conditions, 0 failures, 0 warnings. Four Basic modules end in REVIEW and need their screenshots checked before formal certification.
- [x] Extend `.github/workflows/ci.yml` with `bun run test:node` on Node LTS and with `bun run build` followed by `bun scripts/check-dts.ts`.
- [x] Add `.github/workflows/conformance.yml` (Ubuntu only).
- [x] Write `packages/core/README.md` and replace the template text in the root `README.md`.
- [x] Reserve the `oidc-primitive` name on npm. `0.1.0` is published.
- [x] Decide the default algorithm of `Keys.generate`. It is `RS256`, the ID token algorithm every OpenID Provider must support (OIDC Core s15.1), and the algorithm `ServerMetadata` advertises by default.
- [x] Add cross-tenant isolation tests. A token or assertion made for tenant A must fail at tenant B's `AccessTokenVerifier`, `IdToken.verify`, and `ClientAssertion.verify`. See `packages/core/test/tenant-isolation.test.ts`.
- [x] Add a tenancy section to `docs/host-checklist.md` that covers tenant resolution before any check, storage keyed by issuer, keys per tenant, and per-tenant budgets for outbound fetches.
- [ ] Publish `0.x` releases until the conformance plans pass, then `1.0.0`.

## v1.1: MCP authorization servers and more OIDC profiles

| Module | What it checks or builds | Spec |
| --- | --- | --- |
| `ClientMetadataDocument` | A `client_id` that is an `https` URL with a path, a document whose `client_id` equals that URL, and a public-address check the host runs before it fetches. The host fetches, caches, and caps the response size. | [draft-ietf-oauth-client-id-metadata-document-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), MCP authorization 2026-07-28 |
| `Dpop` | Proof verification (`htm`, `htu`, `iat`, `ath`), the `jkt` thumbprint, and server nonces. It returns the proof `jti` for the host's replay record. `AccessTokenVerifier` accepts a `Dpop` check through its `confirm` option. | [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| `Par` | `request_uri` values with a lifetime under 600 seconds | [RFC 9126](https://www.rfc-editor.org/info/rfc9126), updated by RFC 10070 |
| `DeviceCode` | User codes with enough entropy, input normalization, and the `slow_down` interval | [RFC 8628](https://www.rfc-editor.org/info/rfc8628) |
| `LogoutToken` | Back-channel logout tokens with `typ: logout+jwt`, the `events` claim, `sid` or `sub`, and no `nonce` | [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) |
| `FormPost` | The auto-submitting HTML response with escaped values and a restrictive CSP | [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) |
| `AccessTokenVerifier.forIssuers` | One verifier for several tenants. It reads the unverified `iss`, picks the matching verifier from the host's list, and then runs that verifier. An `iss` outside the list throws `InvalidToken` and fetches no keys. | RFC 9068, RFC 8725 s3.10 |
| `ApiKey` | `generate({ prefix })` returns a `Redacted` key of the form `<prefix>_<secret><checksum>`. `parse` checks the prefix and the CRC32 checksum without a storage lookup, so the host can reject typos and secret scanners can find leaked keys. `verify` compares the key with a stored `OpaqueToken.hash` in constant time. | No standard. The format follows [GitHub's token format](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/). |

RP-initiated logout needs no new module. The host verifies `id_token_hint` with `IdToken.verify({ allowExpired: true })` and matches `post_logout_redirect_uri` with `RedirectUri.matches`.

Conformance gate: Form Post OP, RP-Initiated Logout OP, and Back-Channel Logout OP.

Open decisions for v1.1:

- Dynamic client registration (RFC 7591 and OIDC Registration). The Dynamic OP plan requires it, and a `ClientMetadata.validate` module would share its checks with `ClientMetadataDocument`. MCP marks DCR as deprecated and kept only for backward compatibility. The first plan listed DCR in v1.1, and the current design dropped it.
- An `UnmetAuthenticationRequirements` subclass of `OAuthError`, for `prompt=none` requests that cannot satisfy `max_age` or `acr_values` ([OIDC spec](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html)).

## v1.2: FAPI 2.0 Security Profile

| Module | What it checks or builds | Spec |
| --- | --- | --- |
| FAPI 2.0 preset | One set of stricter defaults: PAR required, DPoP-bound tokens, `private_key_jwt` only, codes that live 60 seconds or less, and `iat` no more than 10 seconds ahead | [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) s5.3.2 |
| `TokenExchange` | Token type identifiers and the `act` claim | [RFC 8693](https://www.rfc-editor.org/info/rfc8693) |
| `StepUp` | The `insufficient_user_authentication` challenge with `acr_values` and `max_age` | [RFC 9470](https://www.rfc-editor.org/info/rfc9470) |

Conformance gate: FAPI 2.0 Security Profile with `private_key_jwt` and DPoP. The mTLS variant waits for RFC 8705 support.

## Later: published specs, built on demand

These specs are final. No milestone holds them yet, and each one needs its own design decision first.

- mTLS client authentication and certificate-bound tokens ([RFC 8705](https://www.rfc-editor.org/info/rfc8705))
- Signed request objects (JAR, [RFC 9101](https://www.rfc-editor.org/info/rfc9101)) and JWT authorization responses (JARM)
- Rich authorization requests ([RFC 9396](https://www.rfc-editor.org/info/rfc9396))
- JWT introspection responses ([RFC 9701](https://www.rfc-editor.org/info/rfc9701))
- FAPI 2.0 Message Signing, which needs HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/info/rfc9421)). The OpenID conformance suite does not test HTTP Message Signatures yet.
- Security Event Tokens ([RFC 8417](https://www.rfc-editor.org/info/rfc8417)) for a Shared Signals transmitter with CAEP events ([SSF 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html), final since 2025-08-29). `LogoutToken` in v1.1 is already a Security Event Token, so the two modules can share code.
- CIBA, OpenID Federation 1.x, and attestation-based client authentication
- Front-channel logout and session management

## Watch list: drafts and runtime changes

Each row names the event that starts design work. Status as of 2026-11-24. Individual drafts stay off this list until an IETF or OpenID Foundation working group adopts them. AAuth, the Workload Authorization Grant, the OAuth Actor Profile, and the transaction-token chaining profile are individual drafts today.

| Feature | What the module would do | Status | Start when |
| --- | --- | --- | --- |
| Post-quantum signatures | Add `ML-DSA-44`, `ML-DSA-65`, and `ML-DSA-87` (key type `AKP`) to the algorithm allow-list, to `Keys.generate`, and to the `*_signing_alg_values_supported` metadata | [RFC 9964](https://www.rfc-editor.org/info/rfc9964) is a Proposed Standard. `jose` supports ML-DSA through Web Crypto since 6.1.0. Web Crypto ML-DSA works on Bun 1.4.4. Node 26.5 prints an `ExperimentalWarning` for it. | Node drops the experimental warning. Hybrid ML-DSA plus ECDSA waits for [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) (draft 06) to become an RFC. |
| JWT bearer grant and ID-JAG | Verify RFC 7523 grant assertions and Identity Assertion Authorization Grant JWTs, including the single-audience and tenant checks. MCP Enterprise-Managed Authorization uses ID-JAG. | [draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) is a working group draft. The parent draft, identity chaining 17, is in the RFC Editor queue. | ID-JAG reaches working group last call. The authors plan to ask for it after draft 07. |
| Transaction tokens | Sign and verify short-lived Txn-Tokens that carry request context inside one trust domain | [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) has working group consensus. The IESG submission milestone is December 2026. | The draft becomes an RFC. Adding this module reverses today's non-goal for internal call chains, so it needs a design decision. |
| Workload client authentication | Accept SPIFFE JWT-SVIDs and WIMSE workload credentials as client assertions in `ClientAssertion` | [draft-ietf-oauth-spiffe-client-auth-03](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/) and [WIMSE workload credentials](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/) are working group drafts. MCP SEP-1933 (Workload Identity Federation) is a draft. | Either IETF draft reaches working group last call, or SEP-1933 becomes final |
| HTTP message signing for MCP clients | Verify RFC 9421 signatures as client authentication. The same module serves FAPI 2.0 Message Signing. | MCP SEP-2752 is a proposal ([SEP tracker](https://plan.modelcontextprotocol.io/seps)) | SEP-2752 is accepted |
| DPoP profile for MCP | Configure `Dpop` defaults for MCP servers | MCP SEP-1932 is a draft | SEP-1932 becomes final |
| Structured authorization denials for MCP | Shape `Bearer.challenge` and `OAuthError` output for the MCP denial format | MCP SEP-2643 is a proposal | SEP-2643 becomes final |
| Enterprise profile (IPSIE) | A preset of defaults, in the same form as the FAPI 2.0 preset | [IPSIE](https://openid.net/wg/ipsie/specifications/) has a v1 draft only. No implementer's draft exists. | IPSIE publishes an implementer's draft |
| OAuth 2.1 as an RFC | Replace draft-17 references and diff the secure defaults against the RFC text and against [draft-ietf-oauth-security-topics-update](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics-update/) (draft 03) | draft-17. The IESG submission milestone is December 2026 ([OAuth WG charter](https://datatracker.ietf.org/wg/oauth/about/)). | Each draft becomes an RFC |
| Client ID Metadata Document as an RFC | Update `ClientMetadataDocument` to the published text | [draft 03](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) is a working group draft | The draft becomes an RFC |
| First-party apps | Primitives for the authorization challenge endpoint | [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/) is waiting for its write-up | The draft becomes an RFC |

## Not planned

- Request parsing, endpoint handlers, flow orchestration, storage, sessions, and login or consent UI
- A client or relying-party library. [oauth4webapi](https://github.com/panva/oauth4webapi) and [openid-client](https://github.com/panva/openid-client) cover that role.
- Implicit, hybrid, and password grants, and `c_hash`
- `client_secret_jwt`
- OID4VCI, OID4VP, and SD-JWT
- A dependency on Effect-TS, a Result library, or a schema library
