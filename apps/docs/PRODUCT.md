# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Astro + Starlight in `apps/docs` of the Bun workspace, deployed to Vercel. Chosen to match the reference docs app the user named (yielded-dev/auth/docs).

## Users

TypeScript backend engineers who build their own OAuth 2.1 Authorization Server, OpenID Provider, or resource server (including MCP authorization servers) and want to own routes, storage, sessions, and UI, without hand-rolling the security checks.

## Product Purpose

`oidc-primitive` is one npm package of security checks and encodings for the server side of OAuth 2.1 and OpenID Connect. Success is a host app that passes the OpenID Foundation conformance plans while every protocol decision stays visible in the host's own code.

## Positioning

Primitives, not a framework. Each module does one spec-cited check or encoding (PKCE, redirect URI matching, ID and access tokens, client authentication, metadata). Web APIs and `jose` only, so it runs on Bun, Node, and edge runtimes. The host owns routes, request parsing, storage, sessions, and UI.

## Operating Context

Readers arrive from npm, GitHub, or a spec search, usually while implementing one endpoint. They read with an RFC open in another tab and copy code into their own handlers. `examples/bun-op` is the single-file reference OP that wires every module.

## Capabilities and Constraints

- Modules: `Pkce`, `RedirectUri`, `Scope`, `Resource`, `ClientSecret`, `ClientAssertion`, `Token`, `IdToken`, `AccessToken`, `TokenSigner`, `Keys`, `AccessTokenVerifier`, `Bearer`, `ResourceMetadata`, `Metadata`, `Claims`, `Introspection`, `OAuthResponse`, `OAuthError`, `Redacted`.
- Pre-1.0. Not published to npm yet. No conformance plan has passed yet.
- Not planned: endpoint handlers, storage, sessions, login or consent UI, a client library, implicit/hybrid/password grants.

## Brand Commitments

Name: `oidc-primitive` (renamed from better-oidc on 2026-11-24). No logo existed before this site.

Visual reference pinned by the user: https://yielded.dev/ and its docs (warm near-black, cream type, IBM Plex Sans and Mono, pill chips with a colored dot, bordered code panels, ownership matrix). Match its craft and grammar with an identity of our own; never reuse yielded's name, mark, or accent.

## Evidence on Hand

- `ROADMAP.md`, `docs/host-checklist.md`, `examples/bun-op`, the test suite under `packages/core/test` (each test cites its RFC section).
- No users, testimonials, benchmarks, or certification. Never claim "certified" or "conformant" until a plan passes.

## Product Principles

- Every check names the spec section it enforces.
- The library decides nothing the host must own.
- Smallest surface that a conformance plan needs.
