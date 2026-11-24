# oidc-primitive

OAuth 2.1 and OpenID Connect security primitives for TypeScript, built on [`jose`](https://github.com/panva/jose). Use them to build your own Authorization Server, OpenID Provider, or resource server. The library checks and encodes; your app owns routes, storage, sessions, and UI.

[![CI](https://github.com/jirayusueb/oidc-primitive/actions/workflows/ci.yml/badge.svg)](https://github.com/jirayusueb/oidc-primitive/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/oidc-primitive)](https://www.npmjs.com/package/oidc-primitive)

```sh
bun add oidc-primitive
```

```ts
import { AccessTokenVerifier, Keys, Pkce, TokenSigner } from 'oidc-primitive';

await Pkce.verify(codeVerifier, storedChallenge); // throws OAuthError.InvalidGrant on mismatch

const signer = TokenSigner.make({ issuer, key: privateKey, kid: 'k1', alg: 'RS256' });
const accessToken = await signer.accessToken({ sub, aud: 'https://api.example.com', client_id: clientId });

const api = AccessTokenVerifier.make({ issuer, audience: 'https://api.example.com', keys: Keys.remoteSet(`${issuer}/jwks`) });
const { claims } = await api.verifyRequest(request.headers);
```

See the [docs](https://oidc-primitive.vercel.app) for guides and the API reference, or the [package README](packages/core/README.md) for every module and its defaults.

## Why

Existing TypeScript providers are whole servers tied to one framework, runtime, user model, or cloud. Writing the protocol yourself repeats known mistakes: plain PKCE, loose redirect matching, client assertions accepted with the token endpoint as audience, access tokens accepted without a `typ` check, and secrets in logs. This library makes the secure choice the default for each of those steps and leaves the rest to you.

- Web APIs and `jose` only. Tested on Bun and Node; nothing in the source ties it to either, so Deno and Workers are targets too.
- Each module is a namespace of functions (`Pkce.verify`, `IdToken.sign`); a few classes bind configuration you reuse.
- Multi-tenant by construction: every issuer-dependent call takes the issuer, and nothing is global.
- OAuth 2.1 draft-17 and RFC 9700 defaults, plus RFC 10070 for client assertions.

## Repository

| Path | Contents |
| --- | --- |
| `packages/core` | The `oidc-primitive` package |
| `apps/docs` | The docs site (Astro Starlight): `bun run docs:dev` |
| `examples/bun-op` | A single-file OpenID Provider built only from the package |
| `conformance` | The OpenID Foundation conformance suite, pinned to v5.3.4, run against `examples/bun-op` |
| `docs/host-checklist.md` | What your app must do that the primitives cannot |
| `ROADMAP.md` | Flows and milestones |

## Development

```sh
bun install
bun run build          # packages/core/dist
bun test               # unit tests on Bun
bun run test:node      # the same tests on Node
bun run type-check
bun run lint
bun run --filter bun-op smoke   # end-to-end flow against the example provider
bun run conformance    # needs Docker; runs the Basic and Config OP plans
```

Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

## License

MIT
